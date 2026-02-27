"""
Osquery queries for AI discovery

These queries work across Windows, macOS, and Linux.
Platform-specific queries are separated.
"""

class AIDiscoveryQueries:
    """SQL queries for finding AI usage via osquery"""
    
    # Desktop Applications
    
    MACOS_AI_APPS = """
    SELECT 
        name,
        bundle_version as version,
        path,
        bundle_identifier
    FROM apps
    WHERE name LIKE '%ChatGPT%'
       OR name LIKE '%Claude%'
       OR name LIKE '%Cursor%'
       OR name LIKE '%Copilot%'
       OR name LIKE '%Tabnine%'
       OR bundle_identifier LIKE '%openai%'
       OR bundle_identifier LIKE '%anthropic%'
       OR bundle_identifier LIKE '%cursor%';
    """
    
    WINDOWS_AI_APPS = """
    SELECT 
        name,
        version,
        install_location as path,
        publisher
    FROM programs
    WHERE name LIKE '%ChatGPT%'
       OR name LIKE '%Claude%'
       OR name LIKE '%Cursor%'
       OR name LIKE '%Copilot%'
       OR name LIKE '%Tabnine%'
       OR publisher LIKE '%OpenAI%'
       OR publisher LIKE '%Anthropic%';
    """
    
    # AI Packages (cross-platform)
    
    PYTHON_AI_PACKAGES = """
    SELECT 
        name,
        version,
        directory as install_path
    FROM python_packages
    WHERE name IN (
        'openai',
        'anthropic', 
        'langchain',
        'llama-index',
        'llama_index',
        'autogen',
        'autogen-agentchat',
        'crewai',
        'semantic-kernel',
        'haystack-ai',
        'transformers',
        'sentence-transformers'
    );
    """
    
    NPM_AI_PACKAGES = """
    SELECT 
        name,
        version,
        directory as install_path
    FROM npm_packages
    WHERE name IN (
        'openai',
        '@anthropic-ai/sdk',
        'langchain',
        '@langchain/core',
        'ai',
        'vercel-ai'
    );
    """
    
    # Active Connections to AI Services via process_open_sockets
    PROCESS_OPEN_SOCKETS = """
    SELECT
        p.name,
        pos.pid,
        pos.remote_address,
        pos.remote_port,
        pos.local_port
    FROM process_open_sockets pos
    JOIN processes p
      ON pos.pid = p.pid
    WHERE pos.remote_port = 443;
    """
    
    # Browser History (Chrome - most common)
    # Includes common AI web frontends (ChatGPT, Claude, Gemini, Perplexity, Poe, HuggingFace, etc.)
    CHROME_AI_HISTORY = """
    SELECT url, title, visit_count, last_visit_time
    FROM chrome_history
    WHERE url LIKE '%chat.openai.com%'
       OR url LIKE '%chatgpt.com%'
       OR url LIKE '%claude.ai%'
       OR url LIKE '%gemini.google.com%'
       OR url LIKE '%perplexity.ai%'
       OR url LIKE '%poe.com%'
       OR url LIKE '%huggingface.co%'
       OR url LIKE '%copilot.microsoft.com%'
       OR url LIKE '%bard.google.com%'
       OR url LIKE '%character.ai%'
       OR url LIKE '%midjourney.com%'
       OR url LIKE '%replicate.com%'
    ORDER BY last_visit_time DESC 
    LIMIT 100;
    """
        
    # Safari AI History (macOS specific)
    SAFARI_AI_HISTORY = """
    SELECT url, title, visit_count, last_visit_time
    FROM safari_history
    WHERE url LIKE '%chat.openai.com%'
       OR url LIKE '%chatgpt.com%'
       OR url LIKE '%claude.ai%'
       OR url LIKE '%gemini.google.com%'
       OR url LIKE '%perplexity.ai%'
       OR url LIKE '%poe.com%'
       OR url LIKE '%huggingface.co%'
       OR url LIKE '%copilot.microsoft.com%'
       OR url LIKE '%bard.google.com%'
       OR url LIKE '%character.ai%'
       OR url LIKE '%midjourney.com%'
       OR url LIKE '%replicate.com%'
    ORDER BY last_visit_time DESC 
    LIMIT 100;
    """
    
    # Edge AI History (Chromium-based)
    EDGE_AI_HISTORY = """
    SELECT url, title, visit_count, last_visit_time
    FROM edge_history
    WHERE url LIKE '%chat.openai.com%'
       OR url LIKE '%chatgpt.com%'
       OR url LIKE '%claude.ai%'
       OR url LIKE '%gemini.google.com%'
       OR url LIKE '%perplexity.ai%'
       OR url LIKE '%poe.com%'
       OR url LIKE '%huggingface.co%'
       OR url LIKE '%copilot.microsoft.com%'
       OR url LIKE '%bard.google.com%'
       OR url LIKE '%character.ai%'
       OR url LIKE '%midjourney.com%'
       OR url LIKE '%replicate.com%'
    ORDER BY last_visit_time DESC 
    LIMIT 100;
    """
    
    # Firefox AI History (via moz_places/Firefox history virtual table)
    FIREFOX_AI_HISTORY = """
    SELECT url, title, visit_count, last_visit_time
    FROM firefox_history
    WHERE url LIKE '%chat.openai.com%'
       OR url LIKE '%chatgpt.com%'
       OR url LIKE '%claude.ai%'
       OR url LIKE '%gemini.google.com%'
       OR url LIKE '%perplexity.ai%'
       OR url LIKE '%poe.com%'
       OR url LIKE '%huggingface.co%'
       OR url LIKE '%copilot.microsoft.com%'
       OR url LIKE '%bard.google.com%'
       OR url LIKE '%character.ai%'
       OR url LIKE '%midjourney.com%'
       OR url LIKE '%replicate.com%'
    ORDER BY last_visit_time DESC 
    LIMIT 100;
    """
    
    # VS Code Extensions (very common for developers)
    
    VSCODE_AI_EXTENSIONS = """
    SELECT 
        name,
        version,
        path
    FROM vscode_extensions
    WHERE name LIKE '%copilot%'
       OR name LIKE '%tabnine%'
       OR name LIKE '%cursor%'
       OR name LIKE '%codeium%'
       OR name LIKE '%openai%';
    """
    
    # Recently modified AI-related files
    
    RECENT_AI_FILES = """
    SELECT 
        path,
        filename,
        size,
        datetime(mtime, 'unixepoch') as modified_time
    FROM file
    WHERE (
        path LIKE '%/training_data/%'
        OR path LIKE '%/prompts/%'
        OR filename LIKE '%.jsonl'
        OR filename LIKE '%prompt%.txt'
        OR filename LIKE '%openai%'
        OR filename LIKE '%anthropic%'
    )
    AND mtime > (strftime('%s', 'now') - 604800)  -- Last 7 days
    LIMIT 50;
    """
    
    @staticmethod
    def get_all_queries(platform: str) -> dict:
        """
        Get all relevant queries for a platform
        
        Args:
            platform: 'darwin' (macOS), 'windows', 'linux'
        
        Returns:
            dict of {query_name: query_sql}
        """
        queries = {
            "python_packages": AIDiscoveryQueries.PYTHON_AI_PACKAGES,
            "npm_packages": AIDiscoveryQueries.NPM_AI_PACKAGES,
            "process_open_sockets": AIDiscoveryQueries.PROCESS_OPEN_SOCKETS,
        }
        
        # Platform-specific queries
        if platform == "darwin":
            queries["desktop_apps"] = AIDiscoveryQueries.MACOS_AI_APPS
            queries["chrome_history"] = AIDiscoveryQueries.CHROME_AI_HISTORY
            queries["safari_history"] = AIDiscoveryQueries.SAFARI_AI_HISTORY
            queries["edge_history"] = AIDiscoveryQueries.EDGE_AI_HISTORY
            queries["firefox_history"] = AIDiscoveryQueries.FIREFOX_AI_HISTORY
            queries["vscode_extensions"] = AIDiscoveryQueries.VSCODE_AI_EXTENSIONS
        elif platform == "windows":
            queries["desktop_apps"] = AIDiscoveryQueries.WINDOWS_AI_APPS
            queries["chrome_history"] = AIDiscoveryQueries.CHROME_AI_HISTORY
            queries["edge_history"] = AIDiscoveryQueries.EDGE_AI_HISTORY
            queries["firefox_history"] = AIDiscoveryQueries.FIREFOX_AI_HISTORY
        else:  # linux
            queries["python_packages"] = AIDiscoveryQueries.PYTHON_AI_PACKAGES
            queries["npm_packages"] = AIDiscoveryQueries.NPM_AI_PACKAGES
            queries["chrome_history"] = AIDiscoveryQueries.CHROME_AI_HISTORY
            queries["firefox_history"] = AIDiscoveryQueries.FIREFOX_AI_HISTORY
        
        return queries
