from typing import Dict

_SENTIMENT_POSITIVE = frozenset({
    "happy", "glad", "great", "awesome", "amazing", "love", "like", "nice",
    "cool", "fun", "funny", "lol", "haha", "rofl", "lmao", "thanks", "thank",
    "appreciate", "helpful", "perfect", "excellent", "wonderful", "fantastic",
    "brilliant", "superb", "outstanding", "impressive", "beautiful", "good",
    "yes", "yeah", "yep", "sure", "ok", "okay", "agree", "correct", "right",
    "welcome", "congrats", "congratulations", "cheers", "gg", "wp", "well done",
    "excited", "thrilled", "delighted", "pleased", "satisfied", "joy", "joyful",
    "blessed", "grateful", "proud", "hope", "hopeful", "optimistic",
    "nice one", "good job", "well played", "noice", "based", "w", "fire",
    "goat", "legend", "king", "queen", "slay", "iconic", "vibes", "mood",
})

_SENTIMENT_NEGATIVE = frozenset({
    "hate", "angry", "mad", "annoyed", "frustrated", "terrible", "awful",
    "horrible", "bad", "worst", "stupid", "idiot", "dumb", "ugly", "fail",
    "failed", "broken", "sucks", "shit", "crap", "damn", "hell", "fucking",
    "no", "nope", "wrong", "disagree", "incorrect", "false", "lie", "lying",
    "scam", "fake", "trash", "garbage", "useless", "pointless", "waste",
    "disappointed", "disappointing", "sad", "unhappy", "miserable", "depressed",
    "frustrating", "annoying", "irritating", "boring", "tired", "exhausted",
    "confused", "lost", "helpless", "hopeless", "pessimistic", "angry",
    "toxic", "drama", "dramatic", "rude", "mean", "cruel", "harsh", "hostile",
    "l", "mid", "cringe", "ratio", "copium", "cope", "seethe", "mad", "salty",
    "triggered", "butthurt", "salty", "butthurt", "cry", "crying", "whine",
})

_SENTIMENT_INTENSIFIERS = frozenset({
    "very", "really", "super", "extremely", "absolutely", "totally", "completely",
    "utterly", "incredibly", "amazingly", "so", "such", "quite", "pretty",
    "highly", "deeply", "strongly", "seriously", "literally", "actually",
})

_SENTIMENT_NEGATORS = frozenset({
    "not", "no", "never", "neither", "nobody", "nothing", "nowhere",
    "don't", "doesn't", "didn't", "won't", "wouldn't", "can't", "cannot",
    "couldn't", "shouldn't", "isn't", "aren't", "wasn't", "weren't",
    "hardly", "barely", "scarcely", "without",
})


class SentimentAnalyzer:
    """Lightweight rule-based sentiment analysis for IRC messages.

    Returns a score in [-1.0, 1.0] where negative = hostile/negative,
    positive = friendly/positive, and 0 = neutral.
    """

    def analyze(self, text: str) -> Dict[str, float]:
        """Return sentiment breakdown for *text*.

        Keys:
          score   – overall sentiment [-1.0, 1.0]
          pos     – positive word count
          neg     – negative word count
          intensity – intensifier multiplier
          is_negated – whether negation was detected
        """
        words = [w.lower().strip(".,!?;:\"'()[]") for w in text.split()]
        if not words:
            return {"score": 0.0, "pos": 0, "neg": 0, "intensity": 1.0, "is_negated": False}

        pos_count = 0
        neg_count = 0
        intensity = 1.0
        negated = False

        for i, w in enumerate(words):
            if w in _SENTIMENT_INTENSIFIERS:
                intensity = min(2.0, intensity + 0.3)
            if w in _SENTIMENT_NEGATORS:
                negated = True
            if w in _SENTIMENT_POSITIVE:
                pos_count += 1
            if w in _SENTIMENT_NEGATIVE:
                neg_count += 1

        # Caps lock = emotional intensity
        if text.isupper() and len(text) > 3:
            intensity = min(2.0, intensity + 0.2)

        # Exclamation marks = intensity
        exclam = text.count("!")
        if exclam > 1:
            intensity = min(2.0, intensity + 0.1 * min(exclam, 5))

        # Question marks = uncertainty (slight negative bias)
        questions = text.count("?")
        if questions > 2:
            neg_count += 1

        raw_score = (pos_count - neg_count) * intensity
        max_possible = max(pos_count + neg_count, 1)
        score = max(-1.0, min(1.0, raw_score / max_possible))

        # Negation flips the polarity
        if negated:
            score = -score * 0.5

        return {
            "score": round(score, 3),
            "pos": pos_count,
            "neg": neg_count,
            "intensity": round(intensity, 2),
            "is_negated": negated,
        }

    def sentiment_label(self, score: float) -> str:
        if score >= 0.5:
            return "very positive"
        if score >= 0.2:
            return "positive"
        if score > -0.2:
            return "neutral"
        if score > -0.5:
            return "negative"
        return "very negative"
