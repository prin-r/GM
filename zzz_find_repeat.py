import collections

f = open("zzz.txt", "r")
l = f.readlines()
f.close()

vl = []
si = []
for ll in l:
    if "ValLuck" in ll:
        vl.append(int(ll.split(" ")[-1], 10))
    if "SaltInt" in ll:
        si.append(int(ll.split(" ")[-1], 10))

print(len(vl))
print(len(si))

print([item for item, count in collections.Counter(vl + si).items() if count > 1])
