from typing import List, Tuple

_TOPIC_KEYWORDS = {
    "programming": {"code", "bug", "debug", "function", "variable", "python", "javascript",
                    "typescript", "rust", "c++", "java", "api", "server", "database", "sql",
                    "git", "commit", "merge", "pull", "branch", "deploy", "docker", "kubernetes",
                    "linux", "windows", "macos", "compiler", "runtime", "library", "framework",
                    "react", "vue", "angular", "node", "npm", "pip", "cargo", "maven"},
    "gaming": {"game", "play", "player", "match", "win", "lose", "score", "level", "boss",
               "raid", "dungeon", "quest", "npc", "pvp", "pve", "mmorpg", "fps", "rpg",
               "steam", "epic", "xbox", "playstation", "nintendo", "switch", "pc", "console",
               "gg", "wp", "noob", "pro", "carry", "feed", "afk", "respawn", "loot", "drop"},
    "anime": {"anime", "manga", "otaku", "waifu", "husband", "senpai", "kawaii", "shonen",
              "shoujo", "seinen", "josei", "isekai", "mecha", "slice of life", "episode",
              "season", "arc", "filler", "canon", "studio", "gibli", "crunchyroll", "funimation",
              "naruto", "one piece", "attack on titan", "demon slayer", "jujutsu", "chainsaw"},
    "music": {"song", "album", "track", "band", "artist", "genre", "rock", "pop", "jazz",
              "classical", "hip hop", "rap", "metal", "electronic", "indie", "folk", "blues",
              "spotify", "apple music", "youtube music", "soundcloud", "bandcamp", "playlist",
              "listen", "hear", "lyrics", "vocals", "guitar", "piano", "drums", "bass"},
    "science": {"science", "physics", "chemistry", "biology", "math", "research", "experiment",
                "theory", "hypothesis", "data", "analysis", "study", "paper", "journal",
                "quantum", "relativity", "evolution", "genetics", "neuroscience", "astronomy",
                "planet", "star", "galaxy", "universe", "black hole", "dark matter"},
    "politics": {"politics", "government", "election", "vote", "president", "congress", "senate",
                 "democrat", "republican", "liberal", "conservative", "policy", "law", "bill",
                 "tax", "budget", "economy", "trade", "war", "peace", "diplomacy", "treaty"},
    "crypto": {"crypto", "bitcoin", "ethereum", "blockchain", "token", "nft", "defi", "wallet",
               "mining", "hash", "consensus", "proof of work", "proof of stake", "exchange",
               "bull", "bear", "hodl", "moon", "lambo", "whale", "diamond hands", "paper hands"},
    "health": {"health", "fitness", "exercise", "diet", "nutrition", "weight", "muscle", "cardio",
               "yoga", "meditation", "sleep", "stress", "anxiety", "depression", "doctor",
               "hospital", "medicine", "vitamin", "supplement", "workout", "gym", "run"},
    "food": {"food", "cook", "recipe", "restaurant", "meal", "breakfast", "lunch", "dinner",
             "snack", "dessert", "pizza", "sushi", "burger", "pasta", "salad", "soup",
             "vegan", "vegetarian", "keto", "paleo", "gluten free", "organic", "fresh"},
    "ai_ml": {"ai", "machine learning", "deep learning", "neural network", "model", "training",
              "inference", "dataset", "label", "feature", "accuracy", "precision", "recall",
              "transformer", "llm", "gpt", "claude", "gemini", "llama", "mistral", "qwen",
              "prompt", "token", "embedding", "vector", "attention", "fine-tune", "rlhf"},
}


class TopicDetector:
    """Detects topics in messages using keyword matching.

    Returns a list of (topic, confidence) pairs for each message.
    """

    def detect(self, text: str) -> List[Tuple[str, float]]:
        """Return list of (topic, confidence) for *text*.

        Confidence is 0..1 based on keyword density.
        """
        text_lower = text.lower()
        words = set(text_lower.split())
        results = []

        for topic, keywords in _TOPIC_KEYWORDS.items():
            hits = words & keywords
            if hits:
                confidence = min(1.0, len(hits) / max(len(keywords) * 0.1, 1))
                results.append((topic, round(confidence, 3)))

        results.sort(key=lambda x: x[1], reverse=True)
        return results[:3]  # Return top 3 topics
