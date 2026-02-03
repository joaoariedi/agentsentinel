import agentsentinel_python

class ThreatAssessment(object):
    def __init__(self, json_data):
        self._inner = agentsentinel_python.PyThreatAssessment(json_data)

    def get_score(self):
        return self._inner.get_score()

    def get_reasons(self):
        return self._inner.get_reasons()
