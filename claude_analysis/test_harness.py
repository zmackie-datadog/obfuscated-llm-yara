#!/usr/bin/env -S uv run
# /// script
# dependencies = [
#     "yara-python>=4.3.1",
# ]
# ///
"""
Test Harness for P4RS3LT0NGV3 Obfuscation Detection

This script tests Yara rules against various obfuscation techniques
used by the P4RS3LT0NGV3 application.
"""

import yara
import os
import sys
from typing import List, Dict, Tuple
import re
import json
from datetime import datetime
import glob

class ObfuscationTestHarness:
    def __init__(self, yara_rule_path: str, test_samples_path: str):
        self.yara_rule_path = yara_rule_path
        self.test_samples_path = test_samples_path
        self.rules = None
        self.test_samples = {}
        self.test_files = []
        self.results = {}
        self.is_directory = os.path.isdir(test_samples_path)
        
    def load_yara_rules(self) -> bool:
        """Load Yara rules from file"""
        try:
            self.rules = yara.compile(filepath=self.yara_rule_path)
            print(f"✓ Loaded Yara rules from {self.yara_rule_path}")
            return True
        except Exception as e:
            print(f"✗ Failed to load Yara rules: {e}")
            return False
    
    def discover_files(self) -> bool:
        """Discover files to test - either from directory or single file"""
        try:
            if self.is_directory:
                # Find all files in directory recursively
                for root, _, files in os.walk(self.test_samples_path):
                    for file in files:
                        # Skip hidden files (files starting with .)
                        if not file.startswith('.'):
                            file_path = os.path.join(root, file)
                            self.test_files.append(file_path)
                
                print(f"✓ Discovered {len(self.test_files)} files in directory {self.test_samples_path}")
                return True
            else:
                # Single file mode - add to test_files list
                self.test_files.append(self.test_samples_path)
                print(f"✓ Using single file: {self.test_samples_path}")
                return True
        except Exception as e:
            print(f"✗ Failed to discover files: {e}")
            return False
    
    def load_test_samples(self) -> bool:
        """Load test samples from file"""
        try:
            with open(self.test_samples_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Parse the test samples file
            for line in content.split('\n'):
                line = line.strip()
                if line and not line.startswith('#') and ':' in line:
                    technique, sample = line.split(':', 1)
                    technique = technique.strip()
                    sample = sample.strip()
                    if sample:  # Only add non-empty samples
                        self.test_samples[technique] = sample
            
            print(f"✓ Loaded {len(self.test_samples)} test samples")
            return True
        except Exception as e:
            print(f"✗ Failed to load test samples: {e}")
            return False
    
    def test_sample(self, technique: str, sample: str) -> Dict:
        """Test a single sample against Yara rules"""
        try:
            # Convert sample to bytes for Yara
            sample_bytes = sample.encode('utf-8')
            
            # Run Yara rules against sample
            matches = self.rules.match(data=sample_bytes)
            
            result = {
                'technique': technique,
                'sample': sample,
                'sample_length': len(sample),
                'matches': [],
                'detected': len(matches) > 0
            }
            
            # Process matches
            for match in matches:
                match_info = {
                    'rule': match.rule,
                    'tags': list(match.tags) if match.tags else [],
                    'strings': []
                }
                
                # Get string matches
                for string_match in match.strings:
                    match_info['strings'].append({
                        'identifier': string_match.identifier,
                        'instances': [
                            {
                                'offset': instance.offset,
                                'match_data': instance.matched_data.decode('utf-8', errors='ignore'),
                                'length': instance.matched_length
                            }
                            for instance in string_match.instances
                        ]
                    })
                
                result['matches'].append(match_info)
            
            return result
            
        except Exception as e:
            return {
                'technique': technique,
                'sample': sample,
                'sample_length': len(sample),
                'error': str(e),
                'detected': False,
                'matches': []
            }
    
    def test_file(self, file_path: str) -> Dict:
        """Test a single file against Yara rules"""
        try:
            # Read file content
            with open(file_path, 'rb') as f:
                file_content = f.read()
            
            # Run Yara rules against file
            matches = self.rules.match(data=file_content)
            
            result = {
                'file_path': file_path,
                'file_name': os.path.basename(file_path),
                'file_size': len(file_content),
                'matches': [],
                'detected': len(matches) > 0
            }
            
            # Process matches
            for match in matches:
                match_info = {
                    'rule': match.rule,
                    'tags': list(match.tags) if match.tags else [],
                    'strings': []
                }
                
                # Get string matches
                for string_match in match.strings:
                    match_info['strings'].append({
                        'identifier': string_match.identifier,
                        'instances': [
                            {
                                'offset': instance.offset,
                                'match_data': instance.matched_data.decode('utf-8', errors='ignore'),
                                'length': instance.matched_length
                            }
                            for instance in string_match.instances
                        ]
                    })
                
                result['matches'].append(match_info)
            
            return result
            
        except Exception as e:
            return {
                'file_path': file_path,
                'file_name': os.path.basename(file_path),
                'file_size': 0,
                'error': str(e),
                'detected': False,
                'matches': []
            }
    
    def run_all_tests(self) -> Dict:
        """Run all tests and return comprehensive results"""
        if self.is_directory:
            return self.run_file_tests()
        else:
            return self.run_sample_tests()
    
    def run_file_tests(self) -> Dict:
        """Run tests on files in directory"""
        print(f"\n🧪 Running tests on {len(self.test_files)} files...")
        print("=" * 80)
        
        total_detected = 0
        total_files = len(self.test_files)
        
        for file_path in self.test_files:
            result = self.test_file(file_path)
            self.results[file_path] = result
            
            # Print result
            status = "✓ DETECTED" if result['detected'] else "✗ CLEAN"
            file_display = result['file_name']
            print(f"{status:12} {file_display:30} | Size: {result['file_size']} bytes")
            
            if result['detected']:
                total_detected += 1
                # Show which rules matched
                for match in result['matches']:
                    print(f"             └─ Rule: {match['rule']}")
        
        print("=" * 80)
        detection_rate = (total_detected/total_files)*100 if total_files > 0 else 0
        print(f"Detection Rate: {total_detected}/{total_files} ({detection_rate:.1f}%)")
        
        return {
            'total_files': total_files,
            'total_detected': total_detected,
            'detection_rate': detection_rate,
            'results': self.results,
            'timestamp': datetime.now().isoformat(),
            'mode': 'directory'
        }
    
    def run_sample_tests(self) -> Dict:
        """Run tests on text samples"""
        print(f"\n🧪 Running tests on {len(self.test_samples)} obfuscation techniques...")
        print("=" * 60)
        
        total_detected = 0
        total_samples = len(self.test_samples)
        
        for technique, sample in self.test_samples.items():
            result = self.test_sample(technique, sample)
            self.results[technique] = result
            
            # Print result
            status = "✓ DETECTED" if result['detected'] else "✗ MISSED"
            print(f"{status:12} {technique:20} | {sample[:50]}{'...' if len(sample) > 50 else ''}")
            
            if result['detected']:
                total_detected += 1
                # Show which rules matched
                for match in result['matches']:
                    print(f"             └─ Rule: {match['rule']}")
        
        print("=" * 60)
        print(f"Detection Rate: {total_detected}/{total_samples} ({(total_detected/total_samples)*100:.1f}%)")
        
        return {
            'total_samples': total_samples,
            'total_detected': total_detected,
            'detection_rate': (total_detected/total_samples)*100,
            'results': self.results,
            'timestamp': datetime.now().isoformat(),
            'mode': 'samples'
        }
    
    def generate_report(self, output_file: str = None) -> str:
        """Generate a detailed test report"""
        if not self.results:
            return "No test results available. Run tests first."
        
        report = []
        report.append("# P4RS3LT0NGV3 Obfuscation Detection Test Report")
        report.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append("")
        
        # Summary
        total_samples = len(self.results)
        detected_samples = sum(1 for r in self.results.values() if r['detected'])
        detection_rate = (detected_samples / total_samples) * 100
        
        report.append("## Summary")
        report.append(f"- Total Techniques Tested: {total_samples}")
        report.append(f"- Techniques Detected: {detected_samples}")
        report.append(f"- Detection Rate: {detection_rate:.1f}%")
        report.append("")
        
        # Detected files/techniques
        if self.is_directory:
            report.append("## Detected Files")
            detected = [r for r in self.results.values() if r['detected']]
            if detected:
                for result in detected:
                    report.append(f"- **{result['file_name']}**: {len(result['matches'])} rule(s) matched")
                    for match in result['matches']:
                        report.append(f"  - Rule: `{match['rule']}`")
            else:
                report.append("None detected.")
            report.append("")
            
            # Missed files
            report.append("## Clean Files")
            missed = [r for r in self.results.values() if not r['detected']]
            if missed:
                for result in missed:
                    report.append(f"- **{result['file_name']}**: {result['file_size']} bytes")
            else:
                report.append("None.")
            report.append("")
            
            # Detailed results
            report.append("## Detailed Results")
            for file_path, result in self.results.items():
                report.append(f"### {result['file_name']}")
                report.append(f"- File: `{result['file_path']}`")
                report.append(f"- Size: {result['file_size']} bytes")
                report.append(f"- Detected: {'✓' if result['detected'] else '✗'}")
                
                if result['matches']:
                    report.append("- Matches:")
                    for match in result['matches']:
                        report.append(f"  - **{match['rule']}**")
                        if match['tags']:
                            report.append(f"    - Tags: {', '.join(match['tags'])}")
                        for string_match in match['strings']:
                            report.append(f"    - String `{string_match['identifier']}`: {len(string_match['instances'])} instance(s)")
                else:
                    report.append("- No matches")
                
                if 'error' in result:
                    report.append(f"- Error: {result['error']}")
                
                report.append("")
        else:
            # Original sample mode
            report.append("## Detected Techniques")
            detected = [r for r in self.results.values() if r['detected']]
            if detected:
                for result in detected:
                    report.append(f"- **{result['technique']}**: {len(result['matches'])} rule(s) matched")
                    for match in result['matches']:
                        report.append(f"  - Rule: `{match['rule']}`")
            else:
                report.append("None detected.")
            report.append("")
            
            # Missed techniques
            report.append("## Missed Techniques")
            missed = [r for r in self.results.values() if not r['detected']]
            if missed:
                for result in missed:
                    report.append(f"- **{result['technique']}**: {result['sample'][:100]}{'...' if len(result['sample']) > 100 else ''}")
            else:
                report.append("None missed.")
            report.append("")
            
            # Detailed results
            report.append("## Detailed Results")
            for technique, result in self.results.items():
                report.append(f"### {technique}")
                report.append(f"- Sample: `{result['sample']}`")
                report.append(f"- Length: {result['sample_length']} characters")
                report.append(f"- Detected: {'✓' if result['detected'] else '✗'}")
                
                if result['matches']:
                    report.append("- Matches:")
                    for match in result['matches']:
                        report.append(f"  - **{match['rule']}**")
                        if match['tags']:
                            report.append(f"    - Tags: {', '.join(match['tags'])}")
                        for string_match in match['strings']:
                            report.append(f"    - String `{string_match['identifier']}`: {len(string_match['instances'])} instance(s)")
                else:
                    report.append("- No matches")
                
                if 'error' in result:
                    report.append(f"- Error: {result['error']}")
                
                report.append("")
        
        report_text = "\n".join(report)
        
        if output_file:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(report_text)
            print(f"\n📄 Report saved to {output_file}")
        
        return report_text
    
    def save_results_json(self, output_file: str):
        """Save results as JSON for further analysis"""
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(self.results, f, indent=2, ensure_ascii=False)
        print(f"📊 JSON results saved to {output_file}")

def main():
    """Main function to run the test harness"""
    if len(sys.argv) < 3:
        print("Usage: python test_harness.py <yara_rule_file> <test_samples_file_or_directory>")
        print("Examples:")
        print("  python test_harness.py obfuscation_detection.yar test_obfuscation_samples.txt")
        print("  python test_harness.py obfuscation_detection.yar ./test_files/")
        sys.exit(1)
    
    yara_rule_path = sys.argv[1]
    test_samples_path = sys.argv[2]
    
    # Check if files/directories exist
    if not os.path.exists(yara_rule_path):
        print(f"Error: Yara rule file not found: {yara_rule_path}")
        sys.exit(1)
    
    if not os.path.exists(test_samples_path):
        print(f"Error: Test samples file/directory not found: {test_samples_path}")
        sys.exit(1)
    
    # Create and run test harness
    harness = ObfuscationTestHarness(yara_rule_path, test_samples_path)
    
    print("🚀 P4RS3LT0NGV3 Obfuscation Detection Test Harness")
    print("=" * 50)
    
    # Load components
    if not harness.load_yara_rules():
        sys.exit(1)
    
    if not harness.discover_files():
        sys.exit(1)
    
    # Load test samples only if not in directory mode
    if not harness.is_directory:
        if not harness.load_test_samples():
            sys.exit(1)
    
    # Run tests
    results = harness.run_all_tests()
    
    # Generate reports
    mode_suffix = "_directory" if harness.is_directory else "_samples"
    report_file = f"test_report{mode_suffix}.md"
    json_file = f"test_results{mode_suffix}.json"
    
    harness.generate_report(report_file)
    harness.save_results_json(json_file)
    
    print(f"\n🎯 Test completed! Detection rate: {results['detection_rate']:.1f}%")

if __name__ == "__main__":
    main()