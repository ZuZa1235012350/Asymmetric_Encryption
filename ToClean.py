import glob

for file in glob.glob("test/*.txt"):
    with open(file, "r+") as f:
        f.truncate()
        f.write("ALA MA KOTA")