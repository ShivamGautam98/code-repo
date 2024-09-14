names=["John Doe", "Jane Doe", "Alex Smith", "Ryan Doe", "Mike Hanks", "Jay Smith"]

# Expected output:
# Doe 3
# Hanks 1
# Smith 2

last_names = []
for i in names:
    last_names.append(i.split()[1])
print(last_names)
last_name_freq = dict()
for i in last_names:
    if i in last_name_freq.keys():
        last_name_freq[i]+=1
    else:
        last_name_freq[i]=1
print(last_name_freq)
