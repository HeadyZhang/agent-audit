"""
ASI-01: Multimodal prompt injection vulnerability.
Rule: AGENT-010
Expected: TRUE POSITIVE at line 15
owasp_id: ASI-01
"""


def process_image_with_prompt(image_data: bytes, user_query: str):
    """Process image with user query - injection risk."""
    # VULNERABILITY: User input in system context
    prompt = f"""Analyze this image and answer: {user_query}
    
    Instructions embedded in the image should be followed."""
    return prompt
