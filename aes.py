import aes_little_functions

Row = list[int]
State = list[Row]

def bytes_to_state(data: bytes ) -> State :
    state: State = [[0, 0, 0, 0] for _ in range(4)]
    i = 0
    for col in range(4):  # go column by column
        for row in range(4):  # fill top to bottom within the column
            state[row][col] = data[i]
            i += 1
    return state

def state_to_bytes(state: State ) -> bytes :
    data = bytearray()
    for col in range(4):
        for row in range(4):
            data.append(state[row][col])
    return bytes(data)

def add_round_key(key: State, state: State ) -> State:
    new_state: State = [[0, 0, 0, 0] for _ in range(4)]
    for col in range(4):
        for row in range(4):
            new_state[row][col] = key[row][col] ^ state[row][col]
    return new_state

def expand_key(key: State) -> list[State]:
    keys: list[State] = [key]
    prev_new_word = None
    for round_num in range(1, 11):
        new_key: State = [[0, 0, 0, 0] for _ in range(4)]
        for col in range(4):
            old_word = aes_little_functions.get_word(key, col)
            if col == 0:
                word_3_after_func = aes_little_functions.apply_core_transform(key, 3, round_num)
                new_word = aes_little_functions.xor_two_words(old_word, word_3_after_func)
            else:
                new_word = aes_little_functions.xor_two_words(prev_new_word, old_word)
            for row in range(4):
                new_key[row][col] = new_word[row]
            prev_new_word = new_word
        keys.append(new_key)
        key = new_key
    return keys

def print_state(state: State) -> None:
    for row in state:
        print(row)

def main():



if __name__ == "__main__":
    main()