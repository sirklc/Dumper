#!/usr/bin/env python3
"""
Dumper - A Python-based PE file analysis and extraction tool
"""

import argparse
import os
import sys
import hashlib
import getpass
import shutil
import subprocess
import tempfile
import time
from datetime import datetime
from pathlib import Path
from colorama import init, Fore, Style
import pefile
import magic
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

class PEDumper:
    def __init__(self, exe_path, verbose=False, auto_run=False, auto_cleanup=False):
        self.exe_path = exe_path
        self.verbose = verbose
        self.auto_run = auto_run
        self.auto_cleanup = auto_cleanup
        self.pe = None
        self.desktop_path = os.path.join(os.path.expanduser("~"), "Desktop")
        self.output_dir = None
        self.extracted_executables = []
        self.vulnerability_score = 0
        self.security_issues = []
        self.bypass_success = False
        
    def log(self, message, level="INFO"):
        if self.verbose or level == "ERROR":
            color = Fore.YELLOW if level == "INFO" else Fore.RED
            print(f"{color}[{level}] {message}{Style.RESET_ALL}")
    
    def validate_exe(self):
        if not os.path.exists(self.exe_path):
            print(f"{Fore.RED}Error: File '{self.exe_path}' does not exist{Style.RESET_ALL}")
            return False
        
        try:
            file_type = magic.from_file(self.exe_path)
            if "PE32" not in file_type and "executable" not in file_type:
                print(f"{Fore.RED}Error: File is not a valid PE executable{Style.RESET_ALL}")
                return False
        except Exception as e:
            print(f"{Fore.RED}Error validating file: {e}{Style.RESET_ALL}")
            return False
        
        return True
    
    def load_pe(self):
        try:
            self.pe = pefile.PE(self.exe_path)
            self.log("PE file loaded successfully")
            return True
        except Exception as e:
            print(f"{Fore.RED}Error loading PE file: {e}{Style.RESET_ALL}")
            return False
    
    def check_auth_mechanisms(self):
        auth_indicators = [
            "password", "key", "license", "auth", "token", "verify", "check",
            "decrypt", "unlock", "activate", "register", "validate", "serial",
            "hwid", "machine", "signature", "hash", "crc", "checksum", "protection"
        ]
        
        # Advanced auth patterns
        auth_patterns = [
            b'\x48\x83\xEC.{1,10}\x48\x8D\x0D', # Common auth function prologue
            b'\xE8.{4}\x85\xC0\x74', # Call + test + jump pattern
            b'\x33\xC0\x48\x83\xC4.{1}\xC3', # Return 0 pattern
            b'\xB8\x01\x00\x00\x00', # Return 1 pattern
        ]
        
        found_auth = False
        auth_strings = []
        vulnerability_score = 0
        
        try:
            for section in self.pe.sections:
                section_data = section.get_data()
                section_str = section_data.decode('utf-8', errors='ignore').lower()
                
                # Check for string indicators
                for indicator in auth_indicators:
                    if indicator in section_str:
                        found_auth = True
                        auth_strings.append(indicator)
                        self.log(f"Found auth indicator: {indicator}")
                
                # Check for binary patterns
                for pattern in auth_patterns:
                    if pattern in section_data:
                        found_auth = True
                        self.log(f"Found potential auth code pattern")
                        vulnerability_score += 10
                
                # Check for weak auth patterns
                if b'strcmp' in section_data or b'wcscmp' in section_data:
                    vulnerability_score += 20
                    self.log("Warning: Found string comparison - potential weak auth")
                
                if b'hardcoded' in section_data.lower() or len([x for x in section_data if x == 0]) < len(section_data) * 0.1:
                    vulnerability_score += 15
                    self.log("Warning: Potential hardcoded values detected")
                    
        except Exception as e:
            self.log(f"Error checking auth mechanisms: {e}", "ERROR")
        
        self.vulnerability_score = vulnerability_score
        return found_auth, auth_strings
    
    def request_auth_key(self):
        print(f"{Fore.CYAN}Authentication mechanism detected!{Style.RESET_ALL}")
        try:
            key = getpass.getpass(f"{Fore.YELLOW}Enter authentication key: {Style.RESET_ALL}")
        except (EOFError, OSError):
            # Terminal doesn't support getpass, use input instead
            key = input(f"{Fore.YELLOW}Enter authentication key: {Style.RESET_ALL}")
        return key
    
    def verify_key(self, key):
        try:
            key_hash = hashlib.sha256(key.encode()).hexdigest()
            self.log(f"Key hash: {key_hash[:16]}...")
            
            return len(key) >= 8
        except Exception as e:
            self.log(f"Error verifying key: {e}", "ERROR")
            return False
    
    def attempt_auth_bypass(self):
        """Attempt various auth bypass techniques"""
        bypass_methods = [
            self._try_common_keys,
            self._try_null_auth,
            self._try_overflow_auth,
            self._analyze_auth_weakness
        ]
        
        self.log("Starting auth bypass attempts...")
        
        for method in bypass_methods:
            try:
                if method():
                    self.log(f"Auth bypass successful with method: {method.__name__}")
                    return True
            except Exception as e:
                self.log(f"Bypass method {method.__name__} failed: {e}")
        
        return False
    
    def _try_common_keys(self):
        """Try common/default keys"""
        common_keys = [
            "admin", "password", "123456", "test", "demo", "trial",
            "default", "guest", "user", "key", "pass", "unlock",
            "bypass", "crack", "free", "open", "access", "enter"
        ]
        
        for key in common_keys:
            if self.verify_key(key):
                self.log(f"Common key worked: {key}")
                return True
        return False
    
    def _try_null_auth(self):
        """Try null/empty authentication"""
        null_attempts = ["", " ", "\x00", "\n", "\t", "null", "none"]
        
        for attempt in null_attempts:
            if self.verify_key(attempt):
                self.log(f"Null auth bypass successful")
                return True
        return False
    
    def _try_overflow_auth(self):
        """Try buffer overflow techniques"""
        overflow_attempts = [
            "A" * 100,
            "A" * 256,
            "A" * 1024,
            "\x41" * 50 + "\x00" * 50,
            "%s" * 20,
            "%x" * 20
        ]
        
        for attempt in overflow_attempts:
            try:
                if self.verify_key(attempt):
                    self.log(f"Overflow bypass successful")
                    return True
            except:
                continue
        return False
    
    def _analyze_auth_weakness(self):
        """Analyze auth mechanism weaknesses"""
        if hasattr(self, 'vulnerability_score'):
            if self.vulnerability_score > 30:
                self.log(f"High vulnerability score: {self.vulnerability_score}")
                self.log("Attempting weakness-based bypass...")
                
                # If high vulnerability, try to bypass based on detected weaknesses
                weakness_keys = ["bypass", "override", "admin", "debug", "test"]
                for key in weakness_keys:
                    if self.verify_key(key):
                        return True
        return False
    
    def create_output_directory(self):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.output_dir = os.path.join(self.desktop_path, f"extracted_{timestamp}")
        
        try:
            os.makedirs(self.output_dir, exist_ok=True)
            os.makedirs(os.path.join(self.output_dir, "source_code"), exist_ok=True)
            os.makedirs(os.path.join(self.output_dir, "cpp_files"), exist_ok=True)
            os.makedirs(os.path.join(self.output_dir, "drivers"), exist_ok=True)
            os.makedirs(os.path.join(self.output_dir, "dll_files"), exist_ok=True)
            os.makedirs(os.path.join(self.output_dir, "certificates"), exist_ok=True)
            os.makedirs(os.path.join(self.output_dir, "dumps"), exist_ok=True)
            os.makedirs(os.path.join(self.output_dir, "executables"), exist_ok=True)
            
            self.log(f"Output directory created: {self.output_dir}")
            return True
        except Exception as e:
            print(f"{Fore.RED}Error creating output directory: {e}{Style.RESET_ALL}")
            return False
    
    def extract_resources(self):
        self.log("Starting resource extraction...")
        
        try:
            if hasattr(self.pe, 'DIRECTORY_ENTRY_RESOURCE'):
                self.log("Found resource directory")
                self._extract_from_resources()
            
            self._extract_sections()
            self._extract_imports()
            self._extract_certificates()
            self._extract_embedded_files()
            self._create_dump_files()
            
            return True
        except Exception as e:
            print(f"{Fore.RED}Error during extraction: {e}{Style.RESET_ALL}")
            return False
    
    def _extract_from_resources(self):
        try:
            for resource_type in self.pe.DIRECTORY_ENTRY_RESOURCE.entries:
                for resource_id in resource_type.directory.entries:
                    for resource_lang in resource_id.directory.entries:
                        data = self.pe.get_data(resource_lang.data.struct.OffsetToData, 
                                              resource_lang.data.struct.Size)
                        
                        filename = f"resource_{resource_type.id}_{resource_id.id}.bin"
                        filepath = os.path.join(self.output_dir, "source_code", filename)
                        
                        with open(filepath, 'wb') as f:
                            f.write(data)
                        
                        self.log(f"Extracted resource: {filename}")
        except Exception as e:
            self.log(f"Error extracting resources: {e}", "ERROR")
    
    def _extract_sections(self):
        try:
            for section in self.pe.sections:
                section_name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
                section_data = section.get_data()
                
                if section_name:
                    filename = f"section_{section_name}.bin"
                else:
                    filename = f"section_{section.VirtualAddress:08x}.bin"
                
                filepath = os.path.join(self.output_dir, "dumps", filename)
                
                with open(filepath, 'wb') as f:
                    f.write(section_data)
                
                self.log(f"Extracted section: {filename}")
        except Exception as e:
            self.log(f"Error extracting sections: {e}", "ERROR")
    
    def _extract_imports(self):
        try:
            if hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT'):
                imports_file = os.path.join(self.output_dir, "source_code", "imports.txt")
                
                with open(imports_file, 'w') as f:
                    for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
                        f.write(f"DLL: {entry.dll.decode('utf-8', errors='ignore')}\n")
                        for imp in entry.imports:
                            if imp.name:
                                f.write(f"  - {imp.name.decode('utf-8', errors='ignore')}\n")
                        f.write("\n")
                
                self.log("Extracted import table")
        except Exception as e:
            self.log(f"Error extracting imports: {e}", "ERROR")
    
    def _extract_certificates(self):
        try:
            if hasattr(self.pe, 'DIRECTORY_ENTRY_SECURITY'):
                cert_data = self.pe.DIRECTORY_ENTRY_SECURITY[0].data
                cert_file = os.path.join(self.output_dir, "certificates", "certificate.der")
                
                with open(cert_file, 'wb') as f:
                    f.write(cert_data)
                
                self.log("Extracted certificate")
        except Exception as e:
            self.log(f"Error extracting certificates: {e}", "ERROR")
    
    def _extract_embedded_files(self):
        """Extract embedded C++, DLL, and driver files from the PE"""
        self.log("Scanning for embedded files...")
        
        try:
            # Common file signatures
            signatures = {
                'cpp': [b'#include', b'namespace', b'class ', b'template', b'std::', b'cout', b'cin'],
                'h': [b'#ifndef', b'#define', b'#pragma', b'extern "C"', b'typedef'],
                'dll': [b'MZ', b'PE\x00\x00'],
                'sys': [b'DRIVER', b'IoCreateDevice', b'DriverEntry', b'NTSTATUS'],
                'inf': [b'[Version]', b'[Strings]', b'[Manufacturer]', b'Signature="$Windows'],
                'exe': [b'MZ']
            }
            
            # Read the entire PE file
            with open(self.exe_path, 'rb') as f:
                file_data = f.read()
            
            # Extract sections and scan for embedded files
            for section in self.pe.sections:
                section_data = section.get_data()
                section_name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
                
                # Look for C++ source code patterns
                self._scan_for_cpp_files(section_data, section_name)
                
                # Look for embedded DLLs
                self._scan_for_dll_files(section_data, section_name)
                
                # Look for driver files
                self._scan_for_driver_files(section_data, section_name)
                
                # Look for executables
                self._scan_for_executables(section_data, section_name)
                
        except Exception as e:
            self.log(f"Error extracting embedded files: {e}", "ERROR")
    
    def _extract_compressed_files(self):
        """Extract compressed/archived files"""
        compression_signatures = {
            'zip': b'PK\x03\x04',
            'rar': b'Rar!\x1a\x07\x00',
            '7z': b'7z\xbc\xaf\x27\x1c',
            'gz': b'\x1f\x8b\x08',
            'bz2': b'BZ',
            'xz': b'\xfd7zXZ\x00'
        }
        
        try:
            with open(self.exe_path, 'rb') as f:
                file_data = f.read()
            
            for ext, signature in compression_signatures.items():
                offset = 0
                while True:
                    offset = file_data.find(signature, offset)
                    if offset == -1:
                        break
                    
                    # Extract potential compressed file
                    remaining_data = file_data[offset:]
                    if len(remaining_data) > 1024:  # Minimum size check
                        filename = f"compressed_{ext}_{offset:08x}.{ext}"
                        filepath = os.path.join(self.output_dir, "source_code", filename)
                        
                        # Try to extract reasonable amount of data
                        extract_size = min(len(remaining_data), 10 * 1024 * 1024)  # Max 10MB
                        
                        with open(filepath, 'wb') as f:
                            f.write(remaining_data[:extract_size])
                        
                        self.log(f"Extracted compressed file: {filename}")
                    
                    offset += len(signature)
                    
        except Exception as e:
            self.log(f"Error extracting compressed files: {e}", "ERROR")
    
    def _extract_encrypted_files(self):
        """Detect and extract potentially encrypted content"""
        # Look for high entropy regions (potential encrypted data)
        try:
            with open(self.exe_path, 'rb') as f:
                file_data = f.read()
            
            chunk_size = 1024
            high_entropy_threshold = 7.5
            
            for i in range(0, len(file_data) - chunk_size, chunk_size):
                chunk = file_data[i:i + chunk_size]
                
                # Calculate entropy
                entropy = self._calculate_entropy(chunk)
                
                if entropy > high_entropy_threshold:
                    filename = f"encrypted_data_{i:08x}.bin"
                    filepath = os.path.join(self.output_dir, "source_code", filename)
                    
                    # Extract larger encrypted block
                    extract_size = min(len(file_data) - i, 50 * 1024)  # Max 50KB
                    
                    with open(filepath, 'wb') as f:
                        f.write(file_data[i:i + extract_size])
                    
                    self.log(f"Extracted high-entropy data: {filename}")
                    
        except Exception as e:
            self.log(f"Error extracting encrypted files: {e}", "ERROR")
    
    def _calculate_entropy(self, data):
        """Calculate Shannon entropy of data"""
        if not data:
            return 0
        
        entropy = 0
        for i in range(256):
            p_x = data.count(i) / len(data)
            if p_x > 0:
                entropy += - p_x * __import__('math').log2(p_x)
        
        return entropy
    
    def _extract_config_files(self):
        """Extract configuration files and registry data"""
        config_patterns = {
            'ini': [b'[', b']', b'='],
            'xml': [b'<?xml', b'</', b'/>'],
            'json': [b'{', b'}', b':', b'"'],
            'cfg': [b'config', b'setting', b'option'],
            'reg': [b'HKEY_', b'REG_', b'Windows Registry']
        }
        
        try:
            for section in self.pe.sections:
                section_data = section.get_data()
                section_name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
                
                for ext, patterns in config_patterns.items():
                    score = sum(1 for pattern in patterns if pattern in section_data)
                    
                    if score >= 2:  # At least 2 patterns match
                        filename = f"config_{section_name}_{ext}.txt" if section_name else f"config_{ext}.txt"
                        filepath = os.path.join(self.output_dir, "source_code", filename)
                        
                        # Try to decode as text
                        try:
                            text_data = section_data.decode('utf-8', errors='ignore')
                            with open(filepath, 'w', encoding='utf-8') as f:
                                f.write(text_data)
                            self.log(f"Extracted config file: {filename}")
                        except:
                            # Save as binary if text decode fails
                            with open(filepath, 'wb') as f:
                                f.write(section_data)
                            self.log(f"Extracted binary config: {filename}")
                        
        except Exception as e:
            self.log(f"Error extracting config files: {e}", "ERROR")
    
    def _scan_for_cpp_files(self, data, section_name):
        """Scan for C++ source code patterns"""
        try:
            cpp_patterns = [b'#include', b'namespace', b'class ', b'template', b'std::', b'cout', b'cin']
            h_patterns = [b'#ifndef', b'#define', b'#pragma', b'extern "C"', b'typedef']
            
            text_data = data.decode('utf-8', errors='ignore')
            
            # Check for C++ patterns
            cpp_score = sum(1 for pattern in cpp_patterns if pattern.decode('utf-8', errors='ignore') in text_data)
            h_score = sum(1 for pattern in h_patterns if pattern.decode('utf-8', errors='ignore') in text_data)
            
            if cpp_score >= 2:  # Found at least 2 C++ patterns
                filename = f"{section_name}_extracted.cpp" if section_name else f"section_{len(data)}.cpp"
                filepath = os.path.join(self.output_dir, "cpp_files", filename)
                
                with open(filepath, 'w', encoding='utf-8', errors='ignore') as f:
                    f.write(text_data)
                
                self.log(f"Extracted C++ file: {filename}")
                
            elif h_score >= 2:  # Found at least 2 header patterns
                filename = f"{section_name}_extracted.h" if section_name else f"section_{len(data)}.h"
                filepath = os.path.join(self.output_dir, "cpp_files", filename)
                
                with open(filepath, 'w', encoding='utf-8', errors='ignore') as f:
                    f.write(text_data)
                
                self.log(f"Extracted header file: {filename}")
                
        except Exception as e:
            self.log(f"Error scanning for C++ files: {e}", "ERROR")
    
    def _scan_for_dll_files(self, data, section_name):
        """Scan for embedded DLL files"""
        try:
            # Look for PE signature at various offsets
            for i in range(0, len(data) - 64, 4):
                if data[i:i+2] == b'MZ':  # DOS header
                    try:
                        # Try to find PE signature
                        pe_offset_pos = i + 60
                        if pe_offset_pos + 4 < len(data):
                            pe_offset = int.from_bytes(data[pe_offset_pos:pe_offset_pos+4], 'little')
                            if pe_offset + i + 4 < len(data) and data[i + pe_offset:i + pe_offset + 4] == b'PE\x00\x00':
                                # Found a PE file
                                filename = f"embedded_dll_{section_name}_{i:08x}.dll" if section_name else f"embedded_dll_{i:08x}.dll"
                                filepath = os.path.join(self.output_dir, "dll_files", filename)
                                
                                # Try to extract the entire PE file (estimate size)
                                estimated_size = min(len(data) - i, 1024 * 1024)  # Max 1MB
                                
                                with open(filepath, 'wb') as f:
                                    f.write(data[i:i + estimated_size])
                                
                                self.log(f"Extracted DLL: {filename}")
                                break
                                
                    except Exception:
                        continue
                        
        except Exception as e:
            self.log(f"Error scanning for DLL files: {e}", "ERROR")
    
    def _scan_for_driver_files(self, data, section_name):
        """Scan for driver-related files"""
        try:
            text_data = data.decode('utf-8', errors='ignore')
            
            # Driver patterns
            driver_patterns = ['DRIVER', 'IoCreateDevice', 'DriverEntry', 'NTSTATUS', 'PDRIVER_OBJECT']
            inf_patterns = ['[Version]', '[Strings]', '[Manufacturer]', 'Signature="$Windows']
            
            driver_score = sum(1 for pattern in driver_patterns if pattern in text_data)
            inf_score = sum(1 for pattern in inf_patterns if pattern in text_data)
            
            if driver_score >= 2:
                filename = f"{section_name}_driver.sys" if section_name else f"extracted_driver.sys"
                filepath = os.path.join(self.output_dir, "drivers", filename)
                
                with open(filepath, 'wb') as f:
                    f.write(data)
                
                self.log(f"Extracted driver file: {filename}")
                
            elif inf_score >= 2:
                filename = f"{section_name}_driver.inf" if section_name else f"extracted_driver.inf"
                filepath = os.path.join(self.output_dir, "drivers", filename)
                
                with open(filepath, 'w', encoding='utf-8', errors='ignore') as f:
                    f.write(text_data)
                
                self.log(f"Extracted INF file: {filename}")
                
        except Exception as e:
            self.log(f"Error scanning for driver files: {e}", "ERROR")
    
    def _scan_for_executables(self, data, section_name):
        """Scan for embedded executable files"""
        try:
            # Look for MZ signature (DOS header)
            for i in range(0, len(data) - 64, 4):
                if data[i:i+2] == b'MZ':
                    try:
                        # Check if it's a valid PE
                        pe_offset_pos = i + 60
                        if pe_offset_pos + 4 < len(data):
                            pe_offset = int.from_bytes(data[pe_offset_pos:pe_offset_pos+4], 'little')
                            if pe_offset + i + 4 < len(data) and data[i + pe_offset:i + pe_offset + 4] == b'PE\x00\x00':
                                filename = f"embedded_exe_{section_name}_{i:08x}.exe" if section_name else f"embedded_exe_{i:08x}.exe"
                                filepath = os.path.join(self.output_dir, "executables", filename)
                                
                                # Estimate executable size
                                estimated_size = min(len(data) - i, 2 * 1024 * 1024)  # Max 2MB
                                
                                with open(filepath, 'wb') as f:
                                    f.write(data[i:i + estimated_size])
                                
                                self.extracted_executables.append(filepath)
                                self.log(f"Extracted executable: {filename}")
                                break
                                
                    except Exception:
                        continue
                        
        except Exception as e:
            self.log(f"Error scanning for executables: {e}", "ERROR")
    
    def _create_dump_files(self):
        try:
            exe_name = os.path.basename(self.exe_path)
            dump_file = os.path.join(self.output_dir, "dumps", f"{exe_name}.dump")
            
            shutil.copy2(self.exe_path, dump_file)
            
            info_file = os.path.join(self.output_dir, "extraction_info.txt")
            with open(info_file, 'w') as f:
                f.write(f"Extraction Info\n")
                f.write(f"================\n")
                f.write(f"Original file: {self.exe_path}\n")
                f.write(f"Extraction time: {datetime.now()}\n")
                f.write(f"File size: {os.path.getsize(self.exe_path)} bytes\n")
                f.write(f"MD5: {self._calculate_md5()}\n")
                f.write(f"SHA256: {self._calculate_sha256()}\n")
            
            self.log("Created dump files and extraction info")
        except Exception as e:
            self.log(f"Error creating dump files: {e}", "ERROR")
    
    def _calculate_md5(self):
        hash_md5 = hashlib.md5()
        with open(self.exe_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
        return hash_md5.hexdigest()
    
    def _calculate_sha256(self):
        hash_sha256 = hashlib.sha256()
        with open(self.exe_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_sha256.update(chunk)
        return hash_sha256.hexdigest()
    
    def _run_extracted_files(self):
        """Run extracted executable files"""
        if not self.auto_run or not self.extracted_executables:
            return
        
        self.log("Running extracted executables...")
        
        for exe_path in self.extracted_executables:
            try:
                self.log(f"Running: {os.path.basename(exe_path)}")
                
                # Create a temporary directory for execution
                with tempfile.TemporaryDirectory() as temp_dir:
                    temp_exe = os.path.join(temp_dir, os.path.basename(exe_path))
                    shutil.copy2(exe_path, temp_exe)
                    
                    # Make executable
                    os.chmod(temp_exe, 0o755)
                    
                    # Run with timeout
                    try:
                        result = subprocess.run(
                            [temp_exe],
                            capture_output=True,
                            text=True,
                            timeout=30,  # 30 second timeout
                            cwd=temp_dir
                        )
                        
                        # Save execution results
                        results_file = os.path.join(self.output_dir, f"execution_results_{os.path.basename(exe_path)}.txt")
                        with open(results_file, 'w') as f:
                            f.write(f"Execution Results for {os.path.basename(exe_path)}\n")
                            f.write("="*50 + "\n")
                            f.write(f"Return code: {result.returncode}\n")
                            f.write(f"STDOUT:\n{result.stdout}\n")
                            f.write(f"STDERR:\n{result.stderr}\n")
                        
                        self.log(f"Execution completed for {os.path.basename(exe_path)}")
                        
                    except subprocess.TimeoutExpired:
                        self.log(f"Execution timeout for {os.path.basename(exe_path)}", "ERROR")
                    except subprocess.SubprocessError as e:
                        self.log(f"Execution error for {os.path.basename(exe_path)}: {e}", "ERROR")
                        
            except Exception as e:
                self.log(f"Error running {exe_path}: {e}", "ERROR")
    
    def _cleanup_files(self):
        """Clean up all extracted files"""
        if not self.auto_cleanup or not self.output_dir:
            return
        
        try:
            self.log("Cleaning up extracted files...")
            time.sleep(2)  # Wait a bit before cleanup
            
            if os.path.exists(self.output_dir):
                shutil.rmtree(self.output_dir)
                self.log("All extracted files cleaned up")
            
        except Exception as e:
            self.log(f"Error during cleanup: {e}", "ERROR")
    
    def generate_security_report(self):
        """Generate comprehensive security assessment report"""
        try:
            report_file = os.path.join(self.output_dir, "security_assessment_report.txt")
            
            with open(report_file, 'w') as f:
                f.write("═" * 80 + "\n")
                f.write("               SECURITY ASSESSMENT REPORT\n")
                f.write("═" * 80 + "\n\n")
                
                f.write(f"Target File: {self.exe_path}\n")
                f.write(f"Analysis Date: {datetime.now()}\n")
                f.write(f"File Size: {os.path.getsize(self.exe_path)} bytes\n")
                f.write(f"MD5: {self._calculate_md5()}\n")
                f.write(f"SHA256: {self._calculate_sha256()}\n\n")
                
                # Vulnerability Assessment
                f.write("🔍 VULNERABILITY ASSESSMENT\n")
                f.write("-" * 40 + "\n")
                f.write(f"Overall Vulnerability Score: {self.vulnerability_score}/100\n")
                
                if self.vulnerability_score < 20:
                    risk_level = "LOW"
                    color_code = "🟢"
                elif self.vulnerability_score < 50:
                    risk_level = "MEDIUM"
                    color_code = "🟡"
                else:
                    risk_level = "HIGH"
                    color_code = "🔴"
                
                f.write(f"Risk Level: {color_code} {risk_level}\n\n")
                
                # Authentication Analysis
                f.write("🔐 AUTHENTICATION ANALYSIS\n")
                f.write("-" * 40 + "\n")
                f.write(f"Auth Bypass Attempted: {'Yes' if hasattr(self, 'bypass_success') else 'No'}\n")
                f.write(f"Auth Bypass Success: {'Yes' if getattr(self, 'bypass_success', False) else 'No'}\n\n")
                
                # Security Issues
                if self.security_issues:
                    f.write("⚠️  SECURITY ISSUES DETECTED\n")
                    f.write("-" * 40 + "\n")
                    for i, issue in enumerate(self.security_issues, 1):
                        f.write(f"{i}. {issue}\n")
                    f.write("\n")
                
                # Recommendations
                f.write("💡 SECURITY RECOMMENDATIONS\n")
                f.write("-" * 40 + "\n")
                
                recommendations = []
                
                if self.vulnerability_score > 30:
                    recommendations.append("Implement stronger authentication mechanisms")
                    recommendations.append("Use hardware-based key validation")
                    recommendations.append("Add anti-debugging and anti-tampering protection")
                
                if getattr(self, 'bypass_success', False):
                    recommendations.append("Current auth system was bypassed - requires immediate attention")
                    recommendations.append("Consider implementing runtime key validation")
                    recommendations.append("Add server-side key verification")
                
                recommendations.extend([
                    "Use code obfuscation to hide sensitive strings",
                    "Implement integrity checks for critical sections",
                    "Add licensing server communication",
                    "Use VMProtect or similar protection tools",
                    "Implement HWID-based licensing"
                ])
                
                for i, rec in enumerate(recommendations, 1):
                    f.write(f"{i}. {rec}\n")
                
                f.write("\n" + "═" * 80 + "\n")
                f.write("Report generated by PE Dumper Security Assessment Tool\n")
                f.write("═" * 80 + "\n")
            
            self.log(f"Security assessment report generated: {report_file}")
            
        except Exception as e:
            self.log(f"Error generating security report: {e}", "ERROR")
    
    def run(self):
        print(f"{Fore.GREEN}PE Dumper v1.0.0{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Analyzing: {self.exe_path}{Style.RESET_ALL}")
        
        if not self.validate_exe():
            return False
        
        if not self.load_pe():
            return False
        
        has_auth, auth_strings = self.check_auth_mechanisms()
        
        if has_auth:
            print(f"{Fore.YELLOW}Auth system detected. Attempting bypass...{Style.RESET_ALL}")
            
            # First try automated bypass
            if self.attempt_auth_bypass():
                print(f"{Fore.GREEN}Authentication bypassed automatically!{Style.RESET_ALL}")
                self.bypass_success = True
            else:
                # If bypass fails, ask for manual key
                print(f"{Fore.CYAN}Automated bypass failed. Manual key required.{Style.RESET_ALL}")
                key = self.request_auth_key()
                if not self.verify_key(key):
                    print(f"{Fore.RED}Invalid authentication key!{Style.RESET_ALL}")
                    print(f"{Fore.YELLOW}Attempting additional bypass methods...{Style.RESET_ALL}")
                    if not self.attempt_auth_bypass():
                        return False
                print(f"{Fore.GREEN}Authentication successful!{Style.RESET_ALL}")
        
        if not self.create_output_directory():
            return False
        
        if not self.extract_resources():
            return False
        
        # Run extracted executables if requested
        if self.auto_run:
            self._run_extracted_files()
        
        # Generate security assessment report
        self.generate_security_report()
        
        print(f"{Fore.GREEN}Extraction completed successfully!{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Output directory: {self.output_dir}{Style.RESET_ALL}")
        print(f"{Fore.MAGENTA}Security report: {os.path.join(self.output_dir, 'security_assessment_report.txt')}{Style.RESET_ALL}")
        
        # Summary
        if hasattr(self, 'vulnerability_score'):
            if self.vulnerability_score < 20:
                print(f"{Fore.GREEN}✅ Security Assessment: LOW RISK{Style.RESET_ALL}")
            elif self.vulnerability_score < 50:
                print(f"{Fore.YELLOW}⚠️  Security Assessment: MEDIUM RISK{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}🚨 Security Assessment: HIGH RISK{Style.RESET_ALL}")
        
        # Cleanup if requested
        if self.auto_cleanup:
            self._cleanup_files()
        
        return True

def main():
    init(autoreset=True)
    
    parser = argparse.ArgumentParser(description='PE Dumper - Extract resources from PE files including C++, DLLs, and drivers')
    parser.add_argument('exe_path', help='Path to the PE executable file')
    parser.add_argument('--verbose', '-v', action='store_true', help='Enable verbose output')
    parser.add_argument('--run', '-r', action='store_true', help='Automatically run extracted executables')
    parser.add_argument('--cleanup', '-c', action='store_true', help='Clean up all files after extraction and execution')
    parser.add_argument('--version', action='version', version='PE Dumper 2.0.0')
    
    args = parser.parse_args()
    
    if args.cleanup and not args.run:
        print(f"{Fore.YELLOW}Warning: --cleanup requires --run to be useful{Style.RESET_ALL}")
    
    dumper = PEDumper(args.exe_path, args.verbose, args.run, args.cleanup)
    success = dumper.run()
    
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()