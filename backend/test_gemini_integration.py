#!/usr/bin/env python3
"""
Test Google Gemini AI Integration for Cybersecurity Platform
Validates that the Google Generative AI is working properly
"""

import asyncio
import sys
import os
import json
from pathlib import Path

# Add the backend directory to the Python path
backend_dir = Path(__file__).parent
sys.path.insert(0, str(backend_dir))

from agents.prompt_engineering.cybersecurity_llm import CyberSecurityLLM
from loguru import logger

async def test_gemini_integration():
    """Test Google Gemini AI integration"""
    
    print("🧪 Testing Google Gemini AI Integration for Cybersecurity Platform")
    print("=" * 70)
    
    # Initialize the cybersecurity LLM with Google provider
    cyber_llm = CyberSecurityLLM(llm_provider="google", model="gemini-1.5-flash")
    
    # Test 1: Check if the client was initialized
    print(f"✅ LLM Provider: {cyber_llm.llm_provider}")
    print(f"✅ Model: {cyber_llm.model}")
    print(f"✅ API Key Available: {'Yes' if cyber_llm.api_key else 'No'}")
    print(f"✅ Client Initialized: {'Yes' if cyber_llm.client else 'No'}")
    
    if not cyber_llm.client:
        print("❌ Google Gemini client not initialized - using local intelligence")
        print()
    else:
        print("🎯 Google Gemini client successfully initialized!")
        print()
    
    # Test 2: Get expert guidance for reconnaissance
    print("🔍 Testing Reconnaissance Expert Guidance:")
    print("-" * 50)
    
    test_context = {
        "target": "hackthissite.org",
        "scan_type": "reconnaissance", 
        "business_context": "security_assessment"
    }
    
    try:
        guidance = await cyber_llm.get_agent_guidance(
            agent_type="reconnaissance",
            task_phase="planning", 
            context=test_context
        )
        
        print(f"📋 Expert: {guidance.get('expert', 'Unknown')}")
        print(f"🎯 Source: {guidance.get('source', 'Unknown')}")
        print(f"📊 Confidence: {guidance.get('confidence', 0)}%")
        print(f"🔬 Methodology: {guidance.get('methodology', 'N/A')}")
        print()
        print("💡 Guidance Preview:")
        guidance_text = guidance.get('guidance', 'No guidance available')
        preview = guidance_text[:300] + "..." if len(guidance_text) > 300 else guidance_text
        print(preview)
        print()
        
        # Check if we're using Google Gemini
        if guidance.get('source') == 'google_gemini':
            print("🎉 SUCCESS: Google Gemini AI is working perfectly!")
            print("🧠 The cybersecurity experts are powered by Google's advanced AI")
        elif guidance.get('source') in ['local_intelligence', 'fallback']:
            print("ℹ️  FALLBACK: Using local intelligence (Google Gemini may not be available)")
        else:
            print(f"🤔 UNKNOWN: Using source '{guidance.get('source')}'")
        
    except Exception as e:
        print(f"❌ ERROR: Failed to get expert guidance: {e}")
        return False
    
    print()
    print("=" * 70)
    print("✅ Google Gemini AI Integration Test Completed")
    return True

async def test_direct_gemini_call():
    """Test direct Google Gemini API call"""
    print()
    print("🚀 Testing Direct Google Gemini API Call:")
    print("-" * 50)
    
    try:
        import google.generativeai as genai
        
        # Configure with the API key
        api_key = "AIzaSyAZJ0lS59gNg2qxp93vd78cL1BGiIyUc7M"
        genai.configure(api_key=api_key)
        
        # Create model
        model = genai.GenerativeModel('gemini-1.5-flash')
        
        # Test prompt
        prompt = """You are a cybersecurity expert. Analyze the target "hackthissite.org" and provide:
1. What type of target this appears to be
2. Recommended reconnaissance approach  
3. Key security considerations

Be professional and concise."""
        
        # Generate response
        response = model.generate_content(prompt)
        
        print("📝 Google Gemini Response:")
        print(response.text[:500] + "..." if len(response.text) > 500 else response.text)
        print()
        print("🎉 SUCCESS: Direct Google Gemini API call works perfectly!")
        
        return True
        
    except ImportError as e:
        print(f"❌ Google GenerativeAI library not available: {e}")
        return False
    except Exception as e:
        print(f"❌ Direct Gemini API call failed: {e}")
        return False

if __name__ == "__main__":
    asyncio.run(test_gemini_integration())
    asyncio.run(test_direct_gemini_call())
