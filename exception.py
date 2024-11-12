import localization as loc


class APIError(Exception):
    def __init__(self, err_no):
        self.err_no = err_no
        self.err_info = loc.err_info.get(err_no, loc.err_info[600])
        pass

    def gen_response_data(self):
        return {
            'status': -1,
            'err_no': self.err_no,
            'err_info': self.err_info
        }

    @classmethod
    def default_response_data(cls):
        return cls(600).gen_response_data()
