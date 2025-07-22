import os
from datetime import datetime
from app import execute_query

# Base passwords
base_passwords = ["Code@2006", "Code2006"]

# Function to generate variations
def generate_variations(password):
    variations = set()
    variations.add(password)
    variations.add(password.lower())
    variations.add(password.upper())
    variations.add(password.capitalize())
    # Leet speak
    leet = password.replace('o', '0').replace('a', '@').replace('e', '3').replace('i', '1').replace('s', '5')
    variations.add(leet)
    # Suffixes/prefixes
    for suffix in ["!", "#", "123", "1", "2023", "2024"]:
        variations.add(password + suffix)
    for prefix in ["123", "!"]:
        variations.add(prefix + password)
    # Year variations
    if "2006" in password:
        for year in ["2023", "2024", "2025"]:
            variations.add(password.replace("2006", year))
    # Reversed
    variations.add(password[::-1])
    # Remove special chars
    variations.add(password.replace("@", "").replace("_", "").replace("-", ""))
    return variations

# Generate all variations
all_passwords = set()
for pwd in base_passwords:
    all_passwords.update(generate_variations(pwd))

# Step 1: Create the wordlist file
wordlist_content = "\n".join(sorted(all_passwords)) + "\n"
wordlist_filename = "wordlist.txt"
wordlist_path = os.path.join(os.path.dirname(__file__), wordlist_filename)

with open(wordlist_path, 'w') as f:
    f.write(wordlist_content)

# Step 2: Insert the wordlist into the database
name = "Generated Wordlist"
description = "Generated variations for Code@2006 and Code2006"
created_at = datetime.now()

wordlist_id = execute_query(
    """INSERT INTO wordlists (name, path, description, created_at)
           VALUES (%s, %s, %s, %s)""",
    (name, wordlist_path, description, created_at)
)

print(f"Wordlist created with ID: {wordlist_id} and path: {wordlist_path}") 