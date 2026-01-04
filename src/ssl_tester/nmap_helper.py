"""Nmap helper functions for vulnerability scanning."""

import logging
import os
import platform
import re
import shutil
import subprocess
from pathlib import Path
from typing import Optional, Tuple

logger = logging.getLogger(__name__)

# Nmap download URLs for different platforms
NMAP_DOWNLOAD_URLS = {
    "Darwin": "https://nmap.org/dist/nmap-7.95.tar.bz2",  # macOS - will need extraction
    "Linux": "https://nmap.org/dist/nmap-7.95-x86_64-portable.tar.xz",  # Linux portable
    "Windows": "https://nmap.org/dist/nmap-7.95-win32.zip",  # Windows
}

# Alternative: Use static binaries if available
NMAP_STATIC_BINARIES = {
    "Darwin": None,  # macOS usually has nmap via Homebrew
    "Linux": "https://github.com/nmap/nmap/releases/download/7.95/nmap-7.95-x86_64-portable.tar.xz",
    "Windows": "https://nmap.org/dist/nmap-7.95-win32.zip",
}


def check_nmap_available() -> Tuple[bool, Optional[str]]:
    """
    Check if nmap is available in system PATH.
    
    Returns:
        Tuple of (is_available, path_to_nmap)
    """
    nmap_path = shutil.which("nmap")
    if nmap_path:
        # Verify it's actually nmap
        try:
            result = subprocess.run(
                [nmap_path, "--version"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0 and "Nmap" in result.stdout:
                logger.debug(f"Found nmap in system PATH: {nmap_path}")
                return True, nmap_path
        except Exception as e:
            logger.debug(f"Error verifying nmap: {e}")
    
    return False, None


def get_nmap_directory() -> Path:
    """
    Get the directory where local nmap binary should be stored.
    
    Returns:
        Path to .nmap directory (in project root or user home)
    """
    # Try project root first (if running from source)
    project_root = Path(__file__).parent.parent.parent
    nmap_dir = project_root / ".nmap"
    
    # If project root doesn't exist or is not writable, use user home
    if not project_root.exists() or not os.access(project_root, os.W_OK):
        nmap_dir = Path.home() / ".ssl_tester" / "nmap"
    
    nmap_dir.mkdir(parents=True, exist_ok=True)
    return nmap_dir


def get_nmap_path() -> Optional[str]:
    """
    Get path to nmap binary (system or local).
    
    Returns:
        Path to nmap binary, or None if not available
    """
    # First check system PATH
    is_available, system_path = check_nmap_available()
    if is_available and system_path:
        return system_path
    
    # Check local binary
    nmap_dir = get_nmap_directory()
    system = platform.system()
    
    if system == "Windows":
        local_nmap = nmap_dir / "nmap.exe"
    else:
        local_nmap = nmap_dir / "nmap"
    
    if local_nmap.exists() and os.access(local_nmap, os.X_OK):
        logger.debug(f"Using local nmap binary: {local_nmap}")
        return str(local_nmap)
    
    return None


def download_nmap() -> bool:
    """
    Download nmap binary for current platform.
    
    Returns:
        True if download successful, False otherwise
    """
    system = platform.system()
    nmap_dir = get_nmap_directory()
    
    logger.info(f"Attempting to download nmap for {system}...")
    
    # For now, we'll use a simpler approach:
    # Try to use package managers first, then fall back to manual download
    
    if system == "Darwin":
        # macOS - try Homebrew
        brew_path = shutil.which("brew")
        if brew_path:
            try:
                logger.info("Installing nmap via Homebrew...")
                result = subprocess.run(
                    [brew_path, "install", "nmap"],
                    capture_output=True,
                    text=True,
                    timeout=300,  # 5 minutes timeout
                )
                if result.returncode == 0:
                    # Check if nmap is now available
                    is_available, nmap_path = check_nmap_available()
                    if is_available:
                        logger.info(f"Successfully installed nmap via Homebrew: {nmap_path}")
                        return True
            except Exception as e:
                logger.debug(f"Homebrew installation failed: {e}")
        
        logger.warning(
            "Automatic nmap download for macOS requires Homebrew. "
            "Please install nmap manually: brew install nmap"
        )
        return False
    
    elif system == "Linux":
        # Linux - try package managers
        package_managers = [
            ("apt-get", ["sudo", "apt-get", "install", "-y", "nmap"]),
            ("yum", ["sudo", "yum", "install", "-y", "nmap"]),
            ("dnf", ["sudo", "dnf", "install", "-y", "nmap"]),
            ("pacman", ["sudo", "pacman", "-S", "--noconfirm", "nmap"]),
        ]
        
        for pm_name, cmd in package_managers:
            pm_path = shutil.which(pm_name.split()[0])
            if pm_path:
                try:
                    logger.info(f"Installing nmap via {pm_name}...")
                    # Note: This requires sudo, which might prompt for password
                    result = subprocess.run(
                        cmd,
                        capture_output=True,
                        text=True,
                        timeout=300,
                    )
                    if result.returncode == 0:
                        is_available, nmap_path = check_nmap_available()
                        if is_available:
                            logger.info(f"Successfully installed nmap via {pm_name}: {nmap_path}")
                            return True
                except Exception as e:
                    logger.debug(f"{pm_name} installation failed: {e}")
                    continue
        
        logger.warning(
            "Automatic nmap installation for Linux requires sudo privileges. "
            "Please install nmap manually: sudo apt-get install nmap (or equivalent)"
        )
        return False
    
    elif system == "Windows":
        # Windows - download portable version
        download_url = NMAP_STATIC_BINARIES.get("Windows")
        if not download_url:
            logger.warning("No download URL available for Windows nmap")
            return False
        
        try:
            logger.info(f"Downloading nmap from {download_url}...")
            # Download would require extraction, which is complex
            # For now, just warn user
            logger.warning(
                "Automatic nmap download for Windows is not yet implemented. "
                "Please download and install nmap manually from: https://nmap.org/download.html"
            )
            return False
        except Exception as e:
            logger.debug(f"Windows nmap download failed: {e}")
            return False
    
    logger.warning(f"Unsupported platform for automatic nmap download: {system}")
    return False


def ensure_nmap_available() -> Tuple[bool, Optional[str]]:
    """
    Ensure nmap is available, download if necessary.
    
    Returns:
        Tuple of (is_available, path_to_nmap)
    """
    # First check if already available
    nmap_path = get_nmap_path()
    if nmap_path:
        return True, nmap_path
    
    # Try to download
    logger.info("nmap not found in system PATH, attempting to install...")
    download_success = download_nmap()
    
    if download_success:
        # Check again after download
        nmap_path = get_nmap_path()
        if nmap_path:
            return True, nmap_path
    
    logger.warning(
        "nmap is not available and automatic installation failed. "
        "Some vulnerability tests will be skipped or use simplified checks. "
        "Please install nmap manually for full vulnerability scanning."
    )
    return False, None


def run_nmap_script(
    host: str,
    port: int,
    script_name: str,
    timeout: float = 10.0,
    ipv6: bool = False,
) -> Tuple[bool, str, str]:
    """
    Run nmap script against target host:port.
    
    Args:
        host: Target hostname
        port: Target port
        script_name: Nmap script name (e.g., "ssl-heartbleed")
        timeout: Timeout in seconds
        ipv6: Use IPv6
        
    Returns:
        Tuple of (success, stdout, stderr)
    """
    nmap_path = get_nmap_path()
    if not nmap_path:
        return False, "", "nmap not available"
    
    try:
        cmd = [
            nmap_path,
            "--script", script_name,
            "-p", str(port),
            "--script-timeout", str(int(timeout)),
            "-Pn",  # Skip ping
        ]
        
        if ipv6:
            cmd.append("-6")
        
        cmd.append(host)
        
        logger.debug(f"Running nmap command: {' '.join(cmd)}")
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout + 5,  # Add buffer for nmap overhead
            check=False,
        )
        
        return True, result.stdout, result.stderr
    
    except subprocess.TimeoutExpired:
        logger.debug(f"nmap script {script_name} timed out for {host}:{port}")
        return False, "", "nmap timeout"
    except FileNotFoundError:
        logger.debug("nmap binary not found")
        return False, "", "nmap not found"
    except Exception as e:
        logger.debug(f"Error running nmap script {script_name}: {e}")
        return False, "", str(e)


def parse_nmap_output(output: str, script_name: str) -> dict:
    """
    Parse nmap script output to extract vulnerability information.
    
    Args:
        output: Nmap stdout
        script_name: Name of the script that produced the output
        
    Returns:
        Dictionary with parsed information:
        {
            "vulnerable": bool,
            "state": str,  # "VULNERABLE", "NOT VULNERABLE", "UNKNOWN"
            "details": list[str],
            "raw_output": str
        }
    """
    result = {
        "vulnerable": False,
        "state": "UNKNOWN",
        "details": [],
        "raw_output": output,
    }
    
    # Common patterns in nmap SSL scripts
    output_upper = output.upper()
    
    # Check for vulnerability state
    state_patterns = [
        (r"STATE:\s*VULNERABLE", "VULNERABLE"),
        (r"STATE:\s*NOT\s+VULNERABLE", "NOT VULNERABLE"),
        (r"STATE:\s*LIKELY\s+VULNERABLE", "VULNERABLE"),
        (r"VULNERABLE:", "VULNERABLE"),
        (r"NOT VULNERABLE:", "NOT VULNERABLE"),
    ]
    
    for pattern, state in state_patterns:
        if re.search(pattern, output, re.IGNORECASE):
            result["state"] = state
            result["vulnerable"] = state == "VULNERABLE"
            break
    
    # Extract additional details
    if "VULNERABLE" in output_upper:
        # Try to extract specific information
        if "read" in output_upper and "bytes" in output_upper:
            bytes_match = re.search(r"read\s+(\d+)\s+bytes", output, re.IGNORECASE)
            if bytes_match:
                result["details"].append(f"Read {bytes_match.group(1)} bytes")
        
        # Extract risk factor if present
        risk_match = re.search(r"Risk\s+factor:\s*(\w+)", output, re.IGNORECASE)
        if risk_match:
            result["details"].append(f"Risk: {risk_match.group(1)}")
    
    # Extract script-specific information
    if script_name == "ssl-heartbleed":
        # Heartbleed specific parsing
        if "heartbleed" in output_upper:
            result["details"].append("Heartbeat extension detected")
    
    elif script_name == "ssl-poodle":
        # POODLE specific parsing
        if "ssl" in output_upper and "3.0" in output_upper:
            result["details"].append("SSL 3.0 support detected")
    
    elif script_name == "ssl-drown":
        # DROWN specific parsing
        if "sslv2" in output_upper or "ssl" in output_upper and "2" in output_upper:
            result["details"].append("SSLv2 support detected")
    
    return result

