import os
import streamlit as st
from dotenv import load_dotenv

from google import genai
from google.genai import types

load_dotenv()

def _get_secret(name: str, default: str | None = None) -> str | None:
    # Prefer Streamlit secrets for deployability, fall back to env vars.
    # Streamlit documents st.secrets usage for local + deployed apps. 【2-ac31fc】【3-6a40c7】
    val = None
    try:
        val = st.secrets.get(name)  # type: ignore[attr-defined]
    except Exception:
        val = None
    return val or os.getenv(name) or default

class LLMClient:
    """
    Reusable Gemini client wrapper (same abstraction as previous homework).
    App code should only depend on `generate(prompt) -> str`.
    """

    def __init__(self, api_key: str, model: str):
        self.model = model
        self.client = genai.Client(api_key=api_key)

    def generate(self, prompt: str, *, temperature: float = 0.2, max_output_tokens: int = 800) -> str:
        resp = self.client.models.generate_content(
            model=self.model,
            contents=prompt,
            config=types.GenerateContentConfig(
                temperature=temperature,
                max_output_tokens=max_output_tokens,
            ),
        )
        return (resp.text or "").strip()

@st.cache_resource(show_spinner=False)
def get_llm() -> LLMClient:
    """
    Cached singleton client — best practice for Streamlit to avoid re-initializing
    on every rerun.
    """
    api_key = _get_secret("GEMINI_API_KEY") or _get_secret("GOOGLE_API_KEY")
    if not api_key:
        raise RuntimeError("Missing GEMINI_API_KEY (set in st.secrets or env vars).")

    model = _get_secret("GEMINI_MODEL", "gemini-2.5-flash-lite")
    return LLMClient(api_key=api_key, model=model)