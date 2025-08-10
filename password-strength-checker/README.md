# Password Strength Checker CLI Tool

A powerful command-line tool that evaluates password strength using regex patterns and entropy calculations.

## Features

- **Multi-criteria evaluation**: Checks for length, uppercase/lowercase letters, numbers, and special characters
- **Entropy calculation**: Calculates password entropy in bits for cryptographic strength assessment
- **Common pattern detection**: Identifies weak patterns like keyboard sequences and repeated characters
- **Color-coded output**: Easy-to-read results with color-coded strength levels
- **Multiple input modes**: Single password, file input, or interactive mode
- **Detailed feedback**: Shows exactly which criteria are met and what needs improvement

## Usage

### Basic Usage
```bash
python password_checker.py "your_password"
```

### Check from file
```bash
python password_checker.py -f passwords.txt
```

### Interactive mode
```bash
python password_checker.py
```

### Verbose output
```bash
python password_checker.py -v "your_password"
```

## Strength Levels

- **Very Strong**: 80%+ score, ≥50 bits entropy, no common patterns
- **Strong**: 60%+ score, ≥35 bits entropy
- **Medium**: 40%+ score, ≥25 bits entropy
- **Weak**: 20%+ score
- **Very Weak**: Below 20% score

## Examples

```bash
# Check a single password
python password_checker.py "MySecureP@ssw0rd123"

# Check multiple passwords from file
python password_checker.py -f my_passwords.txt

# Interactive mode for testing multiple passwords
python password_checker.py
```

## Installation

No additional dependencies required - uses only Python standard library.

## Testing

Test the tool with these example passwords:
- `password` (very weak)
- `Password123` (medium)
- `MyS3cur3P@ss!` (strong)
- `xK9#mP2$vL7@nQ4!` (very strong)
