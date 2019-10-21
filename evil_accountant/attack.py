import json
import pickle

import numpy
from scipy import stats

from evil_accountant.sbox import SBOX

NUM_TRACES = 50


def load_pickled_traces(filename):
    """Pickled dictionary containing the known secret key at the 'key' key stored as an
    ndarray of byte values, an ndarray of power traces under the 'waves' key, and an
    ndarray of plaintexts under the 'plaintexts' key.
    """
    with open(filename, 'rb') as input_file:
        traces = pickle.load(input_file)

    return traces['key'], traces['waves'], traces['plaintexts']


def load_jsoned_traces(filename):
    """same as above but without key and also JSON."""
    with open(filename, 'r') as input_file:
        traces = json.load(input_file)

    return numpy.asarray([43, 126, 21, 22, 40, 174, 210, 166, 171, 247, 21, 136, 9, 207, 79, 60]), numpy.asarray(traces['traces']), numpy.asarray(traces['plaintexts'])


def main():
    #key, traces, plaintexts = load_pickled_traces('traces.pickle')
    key, traces, plaintexts = load_jsoned_traces('traces.json')
    print(numpy.shape(traces))

    ## Limit traces because I don't think we need 6k+
    #traces = traces[1000:1000+NUM_TRACES]
    #plaintexts = plaintexts[1000:1000+NUM_TRACES]

    # This array will be populated by our key guesses
    key_guess = []

    print([hex(x) for x in key])

    # We are splitting up the key into 16 different 1-byte subkeys that will be
    # determined individually.
    for subkey in range(16):
        # Record each guess and it's highest correlation value
        guess_results = []

        # Every possible value of the byte has to be guessed [0, 255]
        for subkey_guess in range(256):
            # We are targeting the intermediate value generated after the first round's
            # AddRoundKey and SubBytes operations. The Hamming Weight of this value will
            # be used as a model for power usage.
            hamming_weights = []

            # Compute the hamming weight of the intermediate value for every plaintext
            for plaintext in plaintexts:
                subbytes_output = SBOX[plaintext[subkey] ^ subkey_guess]
                hamming_weights.append(bin(subbytes_output).count('1'))

            # Convert to a numpy array because it will be faster
            hamming_weights = numpy.asarray(hamming_weights)

            # Calculate the sample Pearson Correlation Coefficient between the model and
            # the measurements for each data point in the traces
            correlations = []
            for idx in range(numpy.shape(traces)[1]):
                measurements = numpy.asarray([trace[idx] for trace in traces])
                r_val, _ = stats.pearsonr(hamming_weights, measurements)
                correlations.append(abs(r_val))

            # Record the results for this subkey guess
            guess_results.append((subkey_guess, max(correlations)))

        # The subkey guess with the highest correlation is our best bet
        guess_results.sort(key=lambda x: x[1], reverse=True)
        key_guess.append(guess_results[0][0])
        print(f'{hex(guess_results[0][0])}, {guess_results[0][1]}')

    print([hex(x) for x in key])
    print([hex(x) for x in key_guess])
