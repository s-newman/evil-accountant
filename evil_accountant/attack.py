import pickle

import numpy
from scipy import stats

from evil_accountant.sbox import SBOX

INPUT_FILE = 'traces.pickle'
NUM_TRACES = 50


def load_traces(filename):
    """Pickled dictionary containing the known secret key at the 'key' key stored as an
    ndarray of byte values, an ndarray of power traces under the 'waves' key, and an
    ndarray of plaintexts under the 'plaintexts' key.
    """
    with open(filename, 'rb') as input_file:
        traces = pickle.load(input_file)

    return traces['key'], traces['waves'], traces['plaintexts']


def main():
    key, traces, plaintexts = load_traces(INPUT_FILE)

    # Limit traces because I don't think we need 6k+
    traces = traces[:NUM_TRACES]
    plaintexts = plaintexts[:NUM_TRACES]

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
                correlations.append(stats.pearsonr(hamming_weights, measurements))

            # Record the results for this subkey guess
            guess_results.append((subkey_guess, max(correlations)))

        # The subkey guess with the highest correlation is our best bet
        guess_results.sort(key=lambda x: x[1], reverse=True)
        key_guess.append(guess_results[0][0])
        print(hex(guess_results[0][0]))
