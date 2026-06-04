import hashlib
import os
import PyPDF2
import docx
import re
from utils.logger import setup_logger
from detection.payload_analyzer import payload_entropy

logger = setup_logger()


def extract_text_from_pdf(file_path):

    text = ""

    try:
        with open(file_path, "rb") as file:

            reader = PyPDF2.PdfReader(file)

            for page in reader.pages:

                page_text = page.extract_text()

                if page_text:
                    text += page_text

    except Exception as e:

        logger.error(f"Error extracting PDF: {str(e)}")

    return text


def extract_text_from_docx(file_path):

    text = ""

    try:

        doc = docx.Document(file_path)

        for paragraph in doc.paragraphs:

            text += paragraph.text + "\n"

    except Exception as e:

        logger.error(f"Error extracting DOCX: {str(e)}")

    return text


def calculate_file_hash(file_path):

    sha256_hash = hashlib.sha256()

    try:

        with open(file_path, "rb") as f:

            for byte_block in iter(lambda: f.read(4096), b""):

                sha256_hash.update(byte_block)

        return sha256_hash.hexdigest()

    except Exception as e:

        logger.error(f"Error calculating hash: {str(e)}")

        return ""


def is_malicious_file_content(file_content):

    if not file_content:
        return 0

    content_lower = file_content.lower()

    suspicious_keywords = [

        "cmd.exe","powershell","wget","curl","nc.exe",
        "reverse shell","backdoor","keylogger",
        "trojan","rootkit","malware","virus",
        "exploit","payload","shellcode"

    ]

    suspicious_patterns = [

        r"<script[^>]*>.*?</script>",
        r"document\.write",
        r"eval\(",
        r"exec\(",
        r"system\(",
        r"subprocess\.",
        r"os\.system",
        r"Runtime\.exec",
        r"ProcessBuilder",
        r"CreateObject\(\"WScript\.Shell\"",
        r"ActiveXObject",
        r"base64_decode",
        r"eval\(base64_decode"

    ]

    keyword_count = sum(
        1 for keyword in suspicious_keywords if keyword in content_lower
    )

    pattern_count = sum(
        1 for pattern in suspicious_patterns
        if re.search(pattern, content_lower, re.IGNORECASE | re.DOTALL)
    )

    entropy = payload_entropy(file_content)

    if keyword_count >= 3 or pattern_count >= 2 or entropy > 7:

        return 1

    return 0

def is_malicious_file(file_hash, file_name=None, file_path=None):
    """
    Heuristic to detect potentially malicious files based on name, hash, or content.
    """
    if not file_hash and not file_path:
        return 0
    
    # Check for known malicious file patterns by extension
    suspicious_patterns = [
        ".exe", ".bat", ".cmd", ".com", ".scr", ".pif",
        ".jar", ".app", ".deb", ".pkg", ".dmg", ".vbs",
        ".js", ".wsf", ".ps1", ".sh", ".php"
    ]
    
    if file_name:
        if any(file_name.lower().endswith(pattern) for pattern in suspicious_patterns):
            return 1
    
    # Check for common malware hashes (simplified example)
    known_malware_hashes = [
        "d41d8cd98f00b204e9800998ecf8427e",  # Example empty file hash
        "44d88612fea8a8f36de82e1278abb02f",  # Example EICAR test hash
    ]
    
    if file_hash and file_hash.lower() in known_malware_hashes:
        return 1
    
    # If file path is provided, check file content for PDF/DOCX files
    if file_path and os.path.exists(file_path):
        file_ext = os.path.splitext(file_path)[1].lower()
        
        if file_ext == '.pdf':
            text_content = extract_text_from_pdf(file_path)
            return is_malicious_file_content(text_content)
        
        elif file_ext == '.docx':
            text_content = extract_text_from_docx(file_path)
            return is_malicious_file_content(text_content)
    
    return 0