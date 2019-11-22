#!/usr/bin/env python
import argparse
import json
from multiprocessing import Pool
from zipfile import ZipFile

from scipy import stats

# fmt: off
SBOX = [
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7,
    0xAB, 0x76, 0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF,
    0x9C, 0xA4, 0x72, 0xC0, 0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5,
    0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15, 0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A,
    0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75, 0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E,
    0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84, 0x53, 0xD1, 0x00, 0xED,
    0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF, 0xD0, 0xEF,
    0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF,
    0xF3, 0xD2, 0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D,
    0x64, 0x5D, 0x19, 0x73, 0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE,
    0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB, 0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C,
    0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79, 0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5,
    0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08, 0xBA, 0x78, 0x25, 0x2E,
    0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A, 0x70, 0x3E,
    0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55,
    0x28, 0xDF, 0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F,
    0xB0, 0x54, 0xBB, 0x16,
]
# fmt: on

KEY = [43, 126, 21, 22, 40, 174, 210, 166, 171, 247, 21, 136, 9, 207, 79, 60]


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "zipfile",
        help="Filename of the challenge zipfile containing the JSON blob of traces.",
    )
    parser.add_argument(
        "-p",
        "--processes",
        type=int,
        help="The number of processes to spawn for multiprocessing. Defaults to 8.",
        default=8,
    )
    return parser.parse_args()


def load_traces(filename):
    with ZipFile(filename, "r") as zipfile:
        with zipfile.open('traces.json') as tracefile:
            traces = json.load(tracefile)

    return (
        KEY,
        traces["traces"],
        traces["plaintexts"],
    )


def power_model(intermediate_value):
    # Hamming weight is used as power model - more 1s, more power usage
    return bin(intermediate_value).count("1")


def get_subkey_guess_correlation(subkey, byte_index, traces, plaintexts):
    # A subkey is one byte
    assert subkey >= 0 and subkey < 256
    # The byte index is the index of the byte of key that is being guessed
    assert byte_index >= 0 and byte_index < 16

    # Store the output of our power usage model for each plaintext/trace pair
    modeled_usage = []

    # Compute the intermediate value for every plaintext and store the results of the
    # power usage model
    for plaintext in plaintexts:
        addkey_output = plaintext[byte_index] ^ subkey
        subbytes_output = SBOX[addkey_output]
        modeled_usage.append(power_model(subbytes_output))

    # Find the correlation coefficient between the modeled power usage and the actual
    # power usage for each data point in the traces (e.g., for point 1 in all traces,
    # for point 2, etc.).
    correlations = []
    for data_point_idx in range(len(traces[0])):
        measurements = [trace[data_point_idx] for trace in traces]
        coefficient = stats.pearsonr(modeled_usage, measurements)
        correlations.append(abs(coefficient[0]))

    # We only return the maximum correlation coefficient of each data point. This
    # eliminates noise in the trace from parts of the encryption unrelated to the
    # intermediate value we're attacking.
    return max(correlations)


def get_correct_subkey_byte(processes, byte_index, traces, plaintexts):
    # The byte index is the index of the byte of key that is being guessed
    assert byte_index >= 0 and byte_index < 16

    # Find the subkey guess with the highest coefficent
    max_coefficent = 0
    best_subkey_guess = 0
    for subkey_guess in range(256):
        guess_coefficient = get_subkey_guess_correlation(
            subkey_guess, byte_index, traces, plaintexts
        )
        if guess_coefficient > max_coefficent:
            max_coefficent = guess_coefficient
            best_subkey_guess = subkey_guess

    return best_subkey_guess, max_coefficent


def get_key(processes, traces, plaintexts):
    key = []

    # Split up the key into 16 different 1-byte subkeys that will be determined
    # individually.
    for idx in range(16):
        key.append(get_correct_subkey_byte(processes, idx, traces, plaintexts))
        print(f'Coefficients: {["%3.2f" % x[1] for x in key]}')
        print(f'Key guess:    {["0x%02x" % x[0] for x in key]}')


def main():
    args = parse_args()
    # Load the traces
    key, traces, plaintexts = load_traces(args.zipfile)
    print(f'Actual key:   {["0x%02x" % x for x in key]}')
    get_key(args.processes, traces, plaintexts)
    print(f'Actual key:   {["0x%02x" % x for x in key]}')


if __name__ == "__main__":
    main()
