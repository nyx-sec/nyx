def first_line(path):
    f = open(path)
    try:
        line = f.readline()
        return line
    finally:
        print("done")
