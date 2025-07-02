id = 1

print("id,src,dst,next,cost")
for src in range(10):
    for dst in range(10):
        if src == dst:
            next = src
        elif dst < src:
            next = src - 1
        else:
            next = src + 1

        cost = abs(src - dst)

        line = ",".join((str(id), str(src), str(dst), str(next), str(cost)))
        id = id+1

        print(line)
