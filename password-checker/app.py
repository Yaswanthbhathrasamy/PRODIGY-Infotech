from flask import Flask, render_template, request
import datetime
import re
import string
import hashlib
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.naive_bayes import MultinomialNB

app = Flask(__name__)

# Define machine learning model (for demonstration purposes, this would need actual training)
model = MultinomialNB()

def train_ml_model():
    # Example training data (passwords with labels: 0 for weak, 1 for strong)
    passwords = ['password', '123456', 'P@ssw0rd!', 'S3cur3P@ss', 'letmein']
    labels = [0, 0, 1, 1, 0]  # 0 = weak, 1 = strong
    vectorizer = CountVectorizer(analyzer='char_wb', ngram_range=(1, 3))
    X = vectorizer.fit_transform(passwords)
    model.fit(X, labels)
    return vectorizer

vectorizer = train_ml_model()

def fetch_threat_intelligence():
    # Simulated function to fetch threat intelligence
    return ["password123", "12345678", "qwerty", "abc123"]

def evaluate_password_strength(password, username, creation_date):
    # Define regex patterns for different criteria
    length_pattern = r".{8,}"  # At least 8 characters
    uppercase_pattern = r"[A-Z]"  # At least one uppercase letter
    lowercase_pattern = r"[a-z]"  # At least one lowercase letter
    digit_pattern = r"\d"  # At least one digit
    special_char_pattern = r"[!@#$%^&*(),.?\":{}|<>]"  # At least one special character
    repeated_chars_pattern = r"(.)\1{2,}"  # Repeated characters (3 or more in a row)
    sequential_patterns = [r"123", r"abc", r"qwerty", r"password"]  # Simple sequential patterns
    keyboard_patterns = [r"qwerty", r"asdfghjkl", r"zxcvbnm"]  # Common keyboard patterns
    leaked_passwords = fetch_threat_intelligence()  # Fetch leaked passwords

    # Initialize score and suggestions
    score = 0
    suggestions = []

    # Check for username or personal information in the password
    if username.lower() in password.lower():
        suggestions.append("Password should not contain your username or personal information.")
    
    # Evaluate each criterion and update the score
    if re.search(length_pattern, password):
        score += 1
    else:
        suggestions.append("Password must be at least 8 characters long.")
    
    if re.search(uppercase_pattern, password):
        score += 1
    else:
        suggestions.append("Password must contain at least one uppercase letter.")
    
    if re.search(lowercase_pattern, password):
        score += 1
    else:
        suggestions.append("Password must contain at least one lowercase letter.")
    
    if re.search(digit_pattern, password):
        score += 1
    else:
        suggestions.append("Password must contain at least one digit.")
    
    if re.search(special_char_pattern, password):
        score += 1
    else:
        suggestions.append("Password must contain at least one special character.")
    
    if re.search(repeated_chars_pattern, password):
        suggestions.append("Avoid using repeated characters.")
    
    if any(re.search(pattern, password) for pattern in sequential_patterns):
        suggestions.append("Avoid using simple sequential patterns like '123' or 'abc'.")
    
    if any(re.search(pattern, password) for pattern in keyboard_patterns):
        suggestions.append("Avoid using common keyboard patterns like 'qwerty'.")
    
    if password.lower() in leaked_passwords:
        return "Password has been leaked in a data breach. Choose a new one."
    
    # Check for repeated sequences
    for seq in set(re.findall(r"(.{2,})", password)):
        if len(seq) > 2 and password.count(seq) > 1:
            suggestions.append(f"Avoid using repeated sequences like '{seq}'.")

    # Password reuse detection (simulated, assuming you have access to a database of previously used passwords)
    used_passwords = set()  # This should be replaced with actual password history in real applications
    if password in used_passwords:
        suggestions.append("This password has been used before. Choose a new one.")

    # Phonetic complexity check (basic simulation)
    def is_phonetic_simple(password):
        simple_patterns = ['password', 'letmein', 'welcome', 'qwerty']
        return any(pattern in password.lower() for pattern in simple_patterns)

    if is_phonetic_simple(password):
        suggestions.append("Avoid using passwords that are phonetically simple or predictable.")

    # Character diversity analysis
    def analyze_character_diversity(password):
        char_sets = {
            'lowercase': string.ascii_lowercase,
            'uppercase': string.ascii_uppercase,
            'digits': string.digits,
            'special': string.punctuation
        }
        char_count = {k: sum(c in v for c in password) for k, v in char_sets.items()}
        diversity_score = sum(count > 0 for count in char_count.values())
        return diversity_score

    diversity = analyze_character_diversity(password)
    if diversity < 3:
        suggestions.append("Increase character diversity by including more types of characters.")

    # Evaluate complexity by position
    def evaluate_position_complexity(password):
        complexity_by_position = sum(
            len(set(password[i:i+3])) > 1 for i in range(len(password) - 2)
        )
        return complexity_by_position

    position_complexity = evaluate_position_complexity(password)
    if position_complexity < 3:
        suggestions.append("Increase complexity by varying characters across different positions.")

    # Multi-language check (basic simulation)
    multi_language_words = ['password', 'salut', 'hola', 'bonjour', 'hallo']
    if any(word in password.lower() for word in multi_language_words):
        suggestions.append("Avoid using common words from multiple languages.")

    # Advanced Pattern Recognition
    def detect_palindromes(password):
        palindromes = [word for word in re.findall(r"\b\w+\b", password.lower()) if word == word[::-1]]
        return palindromes

    palindromes = detect_palindromes(password)
    if palindromes:
        suggestions.append(f"Avoid using palindromes like {', '.join(palindromes)}.")

    # Brute Force Simulation
    def estimate_crack_time(password):
        # Assume 1 billion guesses per second (realistic for modern hardware)
        guesses_per_second = 1e9
        length = len(password)
        char_set_size = len(set(password))  # Simplified
        possible_combinations = char_set_size ** length
        seconds_to_crack = possible_combinations / guesses_per_second
        days_to_crack = seconds_to_crack / (3600 * 24)
        return days_to_crack

    crack_time_days = estimate_crack_time(password)
    if crack_time_days < 1:
        suggestions.append("Password is easy to crack. Consider using a more complex password.")
    elif crack_time_days < 30:
        suggestions.append("Password is moderately complex. Increasing complexity can improve security.")

    # Password Variation Analysis
    def check_variations(password):
        variations = []
        base_password = password.strip()
        for char_set in [string.digits, string.punctuation]:
            for char in char_set:
                variations.append(base_password + char)
                variations.append(char + base_password)
        return variations

    variations = check_variations(password)
    if any(variation in leaked_passwords for variation in variations):
        suggestions.append("Avoid using passwords that are easily guessable with minor variations.")

    # Password Hash Analysis (for demonstration purposes)
    def hash_password(password):
        return hashlib.sha256(password.encode()).hexdigest()

    hashed_password = hash_password(password)
    def evaluate_hash_strength(hashed_password):
        # Simulated hash strength evaluation
        return len(hashed_password)  # For example, just return length

    hash_strength = evaluate_hash_strength(hashed_password)
    if hash_strength < 64:
        suggestions.append("Password hash may be weak. Consider using a stronger hashing algorithm.")

    # Calculate the complexity score
    def calculate_complexity_score(password):
        length_score = len(password) / 2  # Simple length-based score
        diversity_score = analyze_character_diversity(password) * 10  # Weight character diversity
        position_complexity_score = evaluate_position_complexity(password) * 5
        complexity_score = length_score + diversity_score + position_complexity_score
        return complexity_score

    complexity_score = calculate_complexity_score(password)

    # Determine the password strength based on the score
    if complexity_score > 50:
        strength = "Strong password"
    elif complexity_score > 30:
        strength = "Average password"
    else:
        strength = "Weak password"

    # Machine learning model prediction
    password_features = vectorizer.transform([password])
    ml_prediction = model.predict(password_features)[0]
    ml_strength = "Strong password" if ml_prediction == 1 else "Weak password"

    # Provide suggestions if needed
    if suggestions:
        return f"Password is {strength}. Suggestions: {', '.join(suggestions)}. ML Assessment: {ml_strength}"
    
    # Provide numerical strength score
    return f"Password is {strength}. Strength score: {complexity_score}. ML Assessment: {ml_strength}"

@app.route('/', methods=['GET', 'POST'])
def index():
    result = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        creation_date = request.form['creation_date']
        result = evaluate_password_strength(password, username, creation_date)
    return render_template('index.html', result=result)

if __name__ == '__main__':
    app.run(debug=True)
