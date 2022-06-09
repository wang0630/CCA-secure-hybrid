import datetime
from cca_hybrid import *


if __name__ == '__main__':
    print(f'Start Hybrid encryption, using RSA and AES-OFB-256')
    start_time = datetime.datetime.now()
    cca_hybrid_ins = CcaHybrid()
    time_delta = datetime.datetime.now() - start_time
    print(f'End hybrid encryption for RSA and AES-OFB-256, total time: {time_delta.total_seconds()} seconds')

