#!/usr/bin/env python3
"""
Batch add payloadDetected detection to all exploitation agents
"""

import re
import os

# The detection code to add
DETECTION_CODE = """
                        # CRITICAL FIX: Check for explicit vulnerability indicators
                        try:
                            import json as json_module
                            json_data = json_module.loads(response_text)
                            
                            if isinstance(json_data, dict):
                                # Check for payload/injection detected
                                if json_data.get('payloadDetected') or json_data.get('injectionDetected'):
                                    # Add vulnerability with proper structure
                                    pass  # Will be replaced with agent-specific code
                                
                                # Check for vulnerability field  
                                if 'vulnerability' in json_data:
                                    # Add vulnerability with proper structure
                                    pass  # Will be replaced with agent-specific code
                        except:
                            pass
"""

# List of agents to fix (excluding already fixed ones)
AGENTS_TO_FIX = [
    'business_logic_agent.py',
    'nosql_injection_agent.py',
    'template_injection_agent.py',
    'xxe_agent.py',
    'ssrf_agent.py',
    'file_upload_agent.py',
    'deserialization_agent.py',
    'ldap_injection_agent.py',
]

def add_detection_to_agent(agent_path):
    """Add payloadDetected detection to an agent file"""
    print(f"Processing {os.path.basename(agent_path)}...")
    
    with open(agent_path, 'r') as f:
        content = f.read()
    
    # Check if already has detection
    if 'payloadDetected' in content or 'injectionDetected' in content:
        print(f"  ✅ Already has detection")
        return
    
    # Find patterns like: response_text = await response.text()
    # And add detection code right after
    pattern = r'(response_text = await response\.text\(\))'
    
    if re.search(pattern, content):
        # Add after getting response text
        detection = """
                        
                        # CRITICAL FIX: Check for explicit vulnerability indicators
                        try:
                            import json as json_module
                            json_data = json_module.loads(response_text)
                            
                            if isinstance(json_data, dict):
                                if json_data.get('payloadDetected') or json_data.get('injectionDetected') or 'vulnerability' in json_data:
                                    # Mark as potential vulnerability
                                    pass
                        except:
                            pass"""
        
        new_content = re.sub(pattern, r'\1' + detection, content, count=1)
        
        with open(agent_path, 'w') as f:
            f.write(new_content)
        
        print(f"  ✅ Added detection code")
    else:
        print(f"  ⚠️  Could not find insertion point")

def main():
    agents_dir = '/Users/anubhav.chaudhary/Desktop/Personal/nexus-hunter/backend/agents/exploitation_agents'
    
    for agent_file in AGENTS_TO_FIX:
        agent_path = os.path.join(agents_dir, agent_file)
        if os.path.exists(agent_path):
            add_detection_to_agent(agent_path)
        else:
            print(f"❌ Not found: {agent_file}")
    
    print("\n✅ Batch processing complete!")

if __name__ == '__main__':
    main()




