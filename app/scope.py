"""Input scope checks only. These rules never score or classify scam risk."""
import re

SCOPE_MESSAGE = "Paste a link or a message you received so I can check it for scams. I can’t help with general questions or other tasks."

# Reject explicit general-assistant requests; ordinary pasted messages remain valid.
UNRELATED_REQUESTS = re.compile(
    r"^(?:"
    r"(?:hi|hello|hey|thanks|thank you)[!. ]*|"
    r"(?:please\s+)?(?:tell me (?:a joke|a story)|write (?:me )?(?:a poem|a story|an essay|some code|a program)|"
    r"generate (?:an image|a picture|some code)|translate (?:this|the following)|"
    r"(?:what(?:'s| is)|how is) the weather|solve (?:this|the following)|"
    r"(?:who|what) (?:is|was) (?:the president|the capital)|"
    r"ignore (?:all |your |the )?(?:previous |prior )?instructions|"
    r"act as (?:a |an )?(?:chatbot|assistant|developer)|"
    r"help me (?:write|code|cook|solve))\b.*"
    r")$", re.I | re.S,
)


def validate_safety_input(content):
    if UNRELATED_REQUESTS.fullmatch(content.strip()):
        raise ValueError(SCOPE_MESSAGE)
    return content
