class Severity:

    @staticmethod
    def get(score):

        if score >= 80:
            return "CRITICAL"

        if score >= 60:
            return "HIGH"

        if score >= 30:
            return "MEDIUM"

        if score > 0:
            return "LOW"

        return "CLEAN"