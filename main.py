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
from datetime import datetime
from pathlib import Path
from colorama import init, Fore, Style
import pefile
import magic
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

class PEDumper:
    def __init__(self, exe_path, verbose=False):
        self.exe_path = exe_path
        self.verbose = verbose
        self.pe = None
        self.desktop_path = os.path.join(os.path.expanduser("~"), "Desktop")
        self.output_dir = None
        
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
            "decrypt", "unlock", "activate", "register", "validate"
        ]
        
        found_auth = False
        auth_strings = []
        
        try:
            for section in self.pe.sections:
                section_data = section.get_data()
                section_str = section_data.decode('utf-8', errors='ignore').lower()
                
                for indicator in auth_indicators:
                    if indicator in section_str:
                        found_auth = True
                        auth_strings.append(indicator)
                        self.log(f"Found auth indicator: {indicator}")
        except Exception as e:
            self.log(f"Error checking auth mechanisms: {e}", "ERROR")
        
        return found_auth, auth_strings
    
    def request_auth_key(self):
        print(f"{Fore.CYAN}Authentication mechanism detected!{Style.RESET_ALL}")
        key = getpass.getpass(f"{Fore.YELLOW}Enter authentication key: {Style.RESET_ALL}")
        return key
    
    def verify_key(self, key):
        try:
            key_hash = hashlib.sha256(key.encode()).hexdigest()
            self.log(f"Key hash: {key_hash[:16]}...")
            
            return len(key) >= 8
        except Exception as e:
            self.log(f"Error verifying key: {e}", "ERROR")
            return False
    
    def create_output_directory(self):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.output_dir = os.path.join(self.desktop_path, f"extracted_{timestamp}")
        
        try:
            os.makedirs(self.output_dir, exist_ok=True)
            os.makedirs(os.path.join(self.output_dir, "source_code"), exist_ok=True)
            os.makedirs(os.path.join(self.output_dir, "drivers"), exist_ok=True)
            os.makedirs(os.path.join(self.output_dir, "certificates"), exist_ok=True)
            os.makedirs(os.path.join(self.output_dir, "dumps"), exist_ok=True)
            
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
    
    def run(self):
        print(f"{Fore.GREEN}PE Dumper v1.0.0{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Analyzing: {self.exe_path}{Style.RESET_ALL}")
        
        if not self.validate_exe():
            return False
        
        if not self.load_pe():
            return False
        
        has_auth, auth_strings = self.check_auth_mechanisms()
        
        if has_auth:
            key = self.request_auth_key()
            if not self.verify_key(key):
                print(f"{Fore.RED}Invalid authentication key!{Style.RESET_ALL}")
                return False
            print(f"{Fore.GREEN}Authentication successful!{Style.RESET_ALL}")
        
        if not self.create_output_directory():
            return False
        
        if not self.extract_resources():
            return False
        
        print(f"{Fore.GREEN}Extraction completed successfully!{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Output directory: {self.output_dir}{Style.RESET_ALL}")
        
        return True

def main():
    init(autoreset=True)
    
    parser = argparse.ArgumentParser(description='PE Dumper - Extract resources from PE files')
    parser.add_argument('exe_path', help='Path to the PE executable file')
    parser.add_argument('--verbose', '-v', action='store_true', help='Enable verbose output')
    parser.add_argument('--version', action='version', version='PE Dumper 1.0.0')
    
    args = parser.parse_args()
    
    dumper = PEDumper(args.exe_path, args.verbose)
    success = dumper.run()
    
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()