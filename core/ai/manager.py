from typing import Dict, List, Optional

from core.ai.provider import AIProvider

class AIProviderManager:
    def __init__(self, providers: Optional[List[AIProvider]] = None):
        self.providers = providers or []

    def register(self, provider: AIProvider) -> None:
        self.providers.append(provider)

    def available(self) -> List[AIProvider]:
        return [p for p in self.providers if p.is_configured()]

    def get(self, name: str) -> Optional[AIProvider]:
        return next((p for p in self.providers if p.name == name), None)

    def summarize(
        self,
        findings: list[Dict],
        provider_name: Optional[str] = None,
        code_context: Optional[Dict[str, str]] = None,
    ) -> Dict:
        provider = self._select(provider_name)
        if provider is None:
            raise ValueError('No configured AI provider available')
        return {
            'provider': provider.name,
            'summary': provider.summarize_findings(findings, code_context=code_context),
        }

    def enrich_recommendations(
        self,
        findings: list[Dict],
        recommendations: List[Dict],
        provider_name: Optional[str] = None,
        code_context: Optional[Dict[str, str]] = None,
    ) -> Dict:
        provider = self._select(provider_name)
        if provider is None:
            raise ValueError('No configured AI provider available')
        return provider.enrich_fix_recommendations(findings, recommendations, code_context=code_context)

    def _select(self, provider_name: Optional[str]) -> Optional[AIProvider]:
        if provider_name:
            provider = self.get(provider_name)
            if provider and provider.is_configured():
                return provider
            return None
        available = self.available()
        return available[0] if available else None


def build_ai_provider_manager() -> AIProviderManager:
    from core.ai.openai_provider import OpenAIProvider
    from core.ai.ollama_provider import OllamaProvider
    from core.ai.local_stub_provider import LocalStubProvider

    manager = AIProviderManager()
    manager.register(OllamaProvider())
    manager.register(OpenAIProvider())
    manager.register(LocalStubProvider())
    return manager
