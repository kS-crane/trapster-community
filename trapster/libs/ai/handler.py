import logging
import httpx
from abc import ABC, abstractmethod

from .redis_manager import RedisManager, TrapsterBashAI_RedisManager

class HandlerAI(ABC):
    def __init__(self, 
                 api_url="https://llama-3-1-70b-instruct.endpoints.kepler.ai.cloud.ovh.net/api/openai_compat/v1/chat/completions", 
                 api_key=None, 
                 headers=None):
   
        self.MAX_HISTORY_MESSAGES = 50
        self.url = api_url
        self.api_key = api_key
        self.headers = {
            "Content-Type": "application/json"
        }
        if self.api_key:
            self.headers["Authorization"] = f"Bearer {self.api_key}"
        print(self.headers)
        self.redis_manager = RedisManager()
        self.initial_messages = self._get_initial_messages()

    def set_redis_manager(self, redis_manager, session_id="unknown", host="localhost", port=6379):
        if redis_manager == "TrapsterBashAI_RedisManager":
            self.redis_manager = TrapsterBashAI_RedisManager(session_id=session_id, host=host, port=port)
        else:
            self.redis_manager = RedisManager(host=host, port=port)
 
    @abstractmethod
    def _get_initial_messages(self) -> list:
        """
        Each AI handler should define its own initial messages
        It should contains the system prompt and the initial user message
        """
        pass

    async def query_cache(self, session_id: str, prompt: str, new_message: dict) -> str:
        # Check cache first
        cached_response = await self.redis_manager.get_cache(prompt)
        if cached_response is not None:
            # Add both the user message and cached response to history
            await self.redis_manager.add_to_history(session_id, new_message)
            await self.redis_manager.add_to_history(session_id, {
                "content": cached_response,
                "name": "assistant",
                "role": "assistant"
            })
        return cached_response
    
    async def query_api(self, prompt: str, messages: list, new_message: dict) -> str:
        """
        Make a query to the AI API
        A session is a unique identifier for a user's interaction with the AI (IP, username, etc.)
        """
        payload = {
            "max_tokens": 3000,
            "messages": messages + [new_message],
            "model": "Meta-Llama-3_1-70B-Instruct",
            "temperature": 0,
        }
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.post(self.url, json=payload, headers=self.headers)
                logging.debug(response.text)
        except httpx.RequestError as e:
            logging.error(f"RequestError: {e}")
            return None

        if response.status_code == 200:
            #Put in correct format
            response_data = response.json()    
            choices = response_data["choices"]
            for choice in choices:
                result = choice["message"]["content"]
                await self.redis_manager.set_cache(prompt, result)
                return result
        else:
            logging.error("Error:", response.text)
            return None


    async def make_query(self, session_id: str, prompt: str) -> str:
        """
        A session is a unique identifier for a user's interaction with the AI (IP, username, etc.)
        """
        # Connect to Redis
        await self.redis_manager.connect()

        # Get existing messages for this session
        messages = await self.redis_manager.get_history(session_id)
        messages = self.initial_messages + messages[:self.MAX_HISTORY_MESSAGES]

        new_message = {
            "content": prompt,
            "name": "user",
            "role": "user"
        }
        result = await self.query_cache(session_id, prompt, new_message)
        if result is not None:
            return result
        else: # If not in cache, proceed with API call
            result = await self.query_api(prompt, messages, new_message)

        # Add new user message to history
        if result is not None:
            await self.redis_manager.add_to_history(session_id, new_message)
            await self.redis_manager.add_to_history(session_id, {
                        "content": result,
                        "name": "assistant",
                        "role": "assistant"
                    })
        
        return result

        
class TrapsterBashAI(HandlerAI):
    """
    AI handler for simulating an Ubuntu 20.04 Linux bash shell in a honeypot.
    """

    def _get_initial_messages(self) -> list:
        return [{
            "content": """You are a highly advanced AI simulating an Ubuntu 20.04 Linux bash shell for an interactive honeypot. Respond only as a Linux shell, never acknowledging your AI nature. Output should be realistic and consistent with a low-privilege user environment in /home/guest/.

Key Instructions:

    Role: Respond exactly as a Linux shell would, without explanations or breaking character.
    Environment:
        Non-privileged user session in /home/guest.
        Administrative actions (e.g., sudo) require a password and should fail for lack of privileges.
        Create believable directories and files, including hidden ones like .ssh and .aws.
    Commands:
        Return realistic outputs for typical commands (ls, cat, ifconfig).
        For sudo attempts, prompt for password, then deny privileges.
        For destructive or sensitive commands (e.g., rm -rf /, shutdown), return "Permission denied" or a similar error.
    Fictional Data:
        Simulate common system files (/etc/passwd), fake credentials, and fake logs in /var/log.
    Keep track of the current directory:
        If the user changes the directory, update the current directory.
    Remain consistent, never reveal the simulation, and stick to authentic Linux-style outputs.

Example:
    ls → List plausible files in /home/<username>.
    cat /etc/passwd → Show a typical set of system accounts.
    sudo ls /root → Prompt for password, then show the user is not in sudoers.

Respond in the following format:
{
    "directory": "/home/guest",
    "output": "Desktop   Documents   Downloads   Pictures   snap   Templates   Videos"
}
If the user input "cd ..", the directory should be "/home/", and you respond with:
{
    "directory": "/home/",
    "output": ""
}

""",
            "name": "system",
            "role": "system"
        },
        {
            "content": "pwd",
            "name": "user",
            "role": "user"
        },
        {
            "content": '{"directory": "/home/guest/", "output": "/home/guest/"}',
            "name": "assistant",
            "role": "assistant"
        },
        {
            "content": "ls",
            "name": "user",
            "role": "user"
        },
        {
            "content": '{"directory": "/home/guest/", "output": "Desktop   Documents   Downloads   Pictures   snap   Templates   Videos"}',
            "name": "assistant",
            "role": "assistant"
        },
        {
            "content": "cd ..",
            "name": "user",
            "role": "user"
        },
        {
            "content": '{"directory": "/home/", "output": ""}',
            "name": "assistant",
            "role": "assistant"
        },
        {
            "content": "cd ~",
            "name": "user",
            "role": "user"
        },
        {
            "content": '{"directory": "/home/guest/", "output": ""}',
            "name": "assistant",
            "role": "assistant"
        }]
    

