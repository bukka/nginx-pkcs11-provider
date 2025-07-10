import os
import subprocess
import threading
import time
import signal
import sys
from nginx_pkcs11_provider.config import Config


class NginxInstanceManager:
    def __init__(self) -> None:
        self.processes: list[subprocess.Popen[str]] = []
        self.running: bool = True

    def signal_handler(self, signum: int, frame) -> None:
        """Handle shutdown signals gracefully."""
        print(f"\n🛑 Received signal {signum}, shutting down nginx instances...")
        self.stop_all()
        sys.exit(0)

    def stop_all(self) -> None:
        """Stop all running nginx processes."""
        self.running = False
        for process in self.processes:
            if process.poll() is None:  # Process is still running
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
        self.processes.clear()


def run_nginx_instance(config: Config, instance_id: int, manager: NginxInstanceManager) -> bool:
    """Run a single nginx instance with prefixed output for multi-instance scenarios."""
    tmp_dir = config.get_tmp_dir()
    nginx_conf_path = os.path.join(tmp_dir, f"nginx_{instance_id}.conf")

    if not os.path.exists(nginx_conf_path):
        print(f"❌ [Instance {instance_id}] Nginx configuration not found: {nginx_conf_path}")
        return False

    config.load_envs(True)
    config.set_openssl_provider_log(f'nginx_{instance_id}')
    envs = config.get_envs()
    executable = config.get_nginx_executable()

    print(f"🚀 [Instance {instance_id}] Starting: {executable} -c {nginx_conf_path}")

    try:
        process = subprocess.Popen(
            [executable, "-c", nginx_conf_path],
            env=envs,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,  # Merge stderr into stdout
            text=True,
            bufsize=1,  # Line buffered
            universal_newlines=True
        )
        manager.processes.append(process)

        # Stream output with prefix
        while True:
            output = process.stdout.readline() if process.stdout else None
            if output == '' and process.poll() is not None:
                break
            if output:
                print(f"[Instance {instance_id}] {output.rstrip()}")

        returncode = process.poll()

        if returncode != 0 and manager.running:
            print(f"❌ [Instance {instance_id}] Failed with return code {returncode}")
            return False
        elif not manager.running:
            print(f"✅ [Instance {instance_id}] Stopped gracefully")
        else:
            print(f"✅ [Instance {instance_id}] Completed")

        return True

    except Exception as e:
        print(f"❌ [Instance {instance_id}] Failed to start: {e}")
        return False
    """Run a single nginx instance."""
    tmp_dir = config.get_tmp_dir()
    nginx_conf_path = os.path.join(tmp_dir, f"nginx_{instance_id}.conf")

    if not os.path.exists(nginx_conf_path):
        print(f"❌ Nginx configuration for instance {instance_id} not found: {nginx_conf_path}")
        return False

    config.load_envs(True)
    config.set_openssl_provider_log(f'nginx_{instance_id}')
    envs = config.get_envs()
    executable = config.get_nginx_executable()

    print(f"🚀 Starting Nginx instance {instance_id}: {executable} -c {nginx_conf_path}")

    try:
        # For single instance, stream output directly to terminal
        # For multiple instances, we'll need to handle output differently
        process = subprocess.Popen(
            [executable, "-c", nginx_conf_path],
            env=envs
        )
        manager.processes.append(process)

        # Wait for process to complete or be terminated
        returncode = process.wait()

        if returncode != 0 and manager.running:
            print(f"❌ Nginx instance {instance_id} failed with return code {returncode}")
            return False
        elif not manager.running:
            print(f"✅ Nginx instance {instance_id} stopped gracefully")
        else:
            print(f"✅ Nginx instance {instance_id} completed")

        return True

    except Exception as e:
        print(f"❌ Failed to start nginx instance {instance_id}: {e}")
        return False


def get_available_instances(config: Config) -> list[int]:
    """Get list of available nginx instances based on config."""
    instances_count = config.get_nginx_instances_count()
    return list(range(1, instances_count + 1))


def run_nginx(config: Config, instance: int | str | None = None) -> None:
    """
    Runs Nginx using the generated configuration(s).

    Args:
        config: Configuration object
        instance: Which instance(s) to run:
                 - None or "all": Run all available instances
                 - int: Run specific instance number
                 - "list": List available instances and exit
    """
    # Get available instances from config
    instances_count = config.get_nginx_instances_count()
    available_instances = list(range(1, instances_count + 1))

    # Handle different instance parameter values
    if instance == "list":
        if available_instances:
            print(f"📋 Available nginx instances (from config): {instances_count}")
            tmp_dir = config.get_tmp_dir()
            for inst_id in available_instances:
                conf_path = os.path.join(tmp_dir, f"nginx_{inst_id}.conf")
                status = "✅" if os.path.exists(conf_path) else "❌"
                print(f"   {status} Instance {inst_id}: {conf_path}")
        else:
            print("📋 No nginx instances configured.")
        return

    # Determine which instances to run
    instances_to_run: list[int] = []

    if instance is None or instance == "all":
        if available_instances:
            instances_to_run = available_instances
            print(f"🎯 Running all {len(instances_to_run)} nginx instances (configured: {instances_count})")
        else:
            print("❌ No nginx instances configured! Check your config file.")
            return

    elif isinstance(instance, int):
        if 1 <= instance <= instances_count:
            instances_to_run = [instance]
            print(f"🎯 Running nginx instance {instance}")
        else:
            print(f"❌ Nginx instance {instance} not in valid range!")
            print(f"   Valid range: 1-{instances_count} (configured instances: {instances_count})")
            return
    else:
        print(f"❌ Invalid instance parameter: {instance}")
        print(f"   Use: None/'all' (all instances), int (1-{instances_count}), or 'list'")
        return

    # Create instance manager
    manager = NginxInstanceManager()

    # Set up signal handlers for graceful shutdown
    signal.signal(signal.SIGINT, manager.signal_handler)
    signal.signal(signal.SIGTERM, manager.signal_handler)

    # Run instances
    if len(instances_to_run) == 1:
        # Single instance - run in main thread with direct output
        instance_id = instances_to_run[0]
        success = run_nginx_instance(config, instance_id, manager)
        if not success:
            print(f"❌ Failed to start nginx instance {instance_id}")
    else:
        # Multiple instances - run in separate threads with prefixed output
        threads: list[threading.Thread] = []

        for instance_id in instances_to_run:
            thread = threading.Thread(
                target=run_nginx_instance,
                args=(config, instance_id, manager),
                name=f"nginx-{instance_id}"
            )
            thread.daemon = True
            threads.append(thread)
            thread.start()
            time.sleep(0.1)  # Small delay between starts

        print(f"🔄 Started {len(threads)} nginx instances, waiting for completion...")
        print("   Press Ctrl+C to stop all instances")

        try:
            # Wait for all threads to complete
            for thread in threads:
                thread.join()
        except KeyboardInterrupt:
            print("\n🛑 Keyboard interrupt received")
            manager.stop_all()
