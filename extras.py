"""extra.py

Banners and Colors
"""
# ANSI escape sequences
RESET = "\033[0m"
# Foreground
BLACK_FG = "\033[30m"
DARK_RED_FG = "\033[31m"
DARK_GREEN_FG = "\033[32m"
DARK_YELLOW_FG = "\033[33m"
DARK_BLUE_FG = "\033[34m"
DARK_MAGENTA_FG = "\033[35m"
DARK_CYAN_FG = "\033[36m"
DARK_WHITE_FG = "\033[37m"
BRIGHT_BLACK_FG = "\033[90m"
BRIGHT_RED_FG = "\033[91m"
BRIGHT_GREEN_FG = "\033[92m"
BRIGHT_YELLOW_FG = "\033[93m"
BRIGHT_BLUE_FG = "\033[94m"
BRIGHT_MAGENTA_FG = "\033[95m"
BRIGHT_CYAN_FG = "\033[96m"
WHITE_FG = "\033[97m"
# Background
BLACK_BG = "\033[40m"
DARK_RED_BG = "\033[41m"
DARK_GREEN_BG = "\033[42m"
DARK_YELLOW_BG = "\033[43m"
DARK_BLUE_BG = "\033[44m"
DARK_MAGENTA_BG = "\033[45m"
DARK_CYAN_BG = "\033[46m"
DARK_WHITE_BG = "\033[47m"
BRIGHT_BLACK_BG = "\033[100m"
BRIGHT_RED_BG = "\033[101m"
BRIGHT_GREEN_BG = "\033[102m"
BRIGHT_YELLOW_BG = "\033[103m"
BRIGHT_BLUE_BG = "\033[104m"
BRIGHT_MAGENTA_BG = "\033[105m"
BRIGHT_CYAN_BG = "\033[106m"
WHITE_BG = "\033[107m"
# Decorations
BOLD = "\033[1m"
UNDERLINE = "\033[4m"
REVERSE = "\033[7m]"

BLACK_OR_WHITE = [
    BLACK_FG,
    WHITE_FG
]

FOREGROUND = [
    BRIGHT_BLACK_FG,
    BRIGHT_RED_FG,
    BRIGHT_GREEN_FG,
    BRIGHT_YELLOW_FG,
    BRIGHT_BLUE_FG,
    BRIGHT_MAGENTA_FG,
    BRIGHT_CYAN_FG,
    WHITE_FG,
]

BACKGROUND = [
    f"{DARK_RED_BG}",
    f"{DARK_GREEN_BG}",
    f"{DARK_YELLOW_BG}",
    f"{DARK_BLUE_BG}",
    f"{DARK_MAGENTA_BG}",
    f"{DARK_CYAN_BG}",
]

BANNER1 = r"""

 __        ______  _   _             _
 \ \      / / ___|| | | | ___   ___ | | _____ _ __
  \ \ /\ / /\___ \| |_| |/ _ \ / _ \| |/ / _ \ '__|
   \ V  V /  ___) |  _  | (_) | (_) |   <  __/ |
    \_/\_/  |____/|_| |_|\___/ \___/|_|\_\___|_|


"""

BANNER2 = r"""

 _    _ _____ _   _             _
| |  | /  ___| | | |           | |
| |  | \ `--.| |_| | ___   ___ | | _____ _ __
| |/\| |`--. \  _  |/ _ \ / _ \| |/ / _ \ '__|
\  /\  /\__/ / | | | (_) | (_) |   <  __/ |
 \/  \/\____/\_| |_/\___/ \___/|_|\_\___|_|


"""

BANNER3 = r"""

 __    __  __                    _
/ / /\ \ \/ _\  /\  /\___   ___ | | _____ _ __
\ \/  \/ /\ \  / /_/ / _ \ / _ \| |/ / _ \ '__|
 \  /\  / _\ \/ __  / (_) | (_) |   <  __/ |
  \/  \/  \__/\/ /_/ \___/ \___/|_|\_\___|_|


"""

BANNER4 = r"""

 _       _______ __  __            __
| |     / / ___// / / /___  ____  / /_____  _____
| | /| / /\__ \/ /_/ / __ \/ __ \/ //_/ _ \/ ___/
| |/ |/ /___/ / __  / /_/ / /_/ / ,< /  __/ /
|__/|__//____/_/ /_/\____/\____/_/|_|\___/_/


"""

BANNER5 = r"""

 __        ______  _   _             _
 \ \      / / ___|| | | | ___   ___ | | _____ _ __
  \ \ /\ / /\___ \| |_| |/ _ \ / _ \| |/ / _ \ '__|
   \ V  V /  ___) |  _  | (_) | (_) |   <  __/ |
    \_/\_/  |____/|_| |_|\___/ \___/|_|\_\___|_|


"""

BANNER6 = r'''

__      __ ___    _  _                     _
\ \    / // __|  | || |    ___     ___    | |__    ___      _ _
 \ \/\/ / \__ \  | __ |   / _ \   / _ \   | / /   / -_)    | '_|
  \_/\_/  |___/  |_||_|   \___/   \___/   |_\_\   \___|   _|_|_
_|"""""|_|"""""|_|"""""|_|"""""|_|"""""|_|"""""|_|"""""|_|"""""|
"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'


'''

BANNER7 = r"""

 ____      ____   ______   ____  ____                __
|_  _|    |_  _|.' ____ \ |_   ||   _|              [  |  _
  \ \  /\  / /  | (___ \_|  | |__| |   .--.    .--.  | | / ] .---.  _ .--.
   \ \/  \/ /    _.____`.   |  __  | / .'`\ \/ .'`\ \| '' < / /__\\[ `/'`\]
    \  /\  /    | \____) | _| |  | |_| \__. || \__. || |`\ \| \__., | |
     \/  \/      \______.'|____||____|'.__.'  '.__.'[__|  \_]'.__.'[___]


"""

BANNER8 = r"""


 _|          _|    _|_|_|  _|    _|                      _|
 _|          _|  _|        _|    _|    _|_|      _|_|    _|  _|      _|_|    _|  _|_|
 _|    _|    _|    _|_|    _|_|_|_|  _|    _|  _|    _|  _|_|      _|_|_|_|  _|_|
   _|  _|  _|          _|  _|    _|  _|    _|  _|    _|  _|  _|    _|        _|
     _|  _|      _|_|_|    _|    _|    _|_|      _|_|    _|    _|    _|_|_|  _|


"""

BANNER9 = r"""

 ________ _______ _______               __
|  |  |  |     __|   |   |.-----.-----.|  |--.-----.----.
|  |  |  |__     |       ||  _  |  _  ||    <|  -__|   _|
|________|_______|___|___||_____|_____||__|__|_____|__|


"""

BANNER10 = r"""

888       888  .d8888b.  888    888                   888
888   o   888 d88P  Y88b 888    888                   888
888  d8b  888 Y88b.      888    888                   888
888 d888b 888  "Y888b.   8888888888  .d88b.   .d88b.  888  888  .d88b.  888d888
888d88888b888     "Y88b. 888    888 d88""88b d88""88b 888 .88P d8P  Y8b 888P"
88888P Y88888       "888 888    888 888  888 888  888 888888K  88888888 888
8888P   Y8888 Y88b  d88P 888    888 Y88..88P Y88..88P 888 "88b Y8b.     888
888P     Y888  "Y8888P"  888    888  "Y88P"   "Y88P"  888  888  "Y8888  888


"""

BANNERS = [
    BANNER1,
    BANNER2,
    BANNER3,
    BANNER4,
    BANNER5,
    BANNER6,
    BANNER7,
    BANNER8,
    BANNER9,
    BANNER10,
]

PERLISISMS = [
    "One man's constant is another man's variable.",
    "Syntactic sugar causes cancer of the semicolon.",
    "Every program is a part of some other program and rarely fits.",
    "It is easier to write an incorrect program than understand a correct one.",
    "If you have a procedure with ten parameters, you probably missed some.",
    "Recursion is the root of computation since it trades description for time.",
    "In the long run every program becomes rococo - then rubble.",
    "Everything should be built top-down, except the first time.",
    "If a listener nods his head when you're explaining your program, wake him up.",
    "A program without a loop and a structured variable isn't worth writing.",
    "Optimization hinders evolution.",
    "A good system can't have a weak command language.",
    "To understand a program you must become both the machine and the program.",
    "Once you understand how to write a program get someone else to write it.",
    "Simplicity does not precede complexity, but follows it.",
    "Structured Programming supports the law of the excluded middle.",
    "There are two ways to write error-free programs; only the third one works.",
    "Some programming languages manage to absorb change, but withstand progress.",
    "In software systems, it is often the early bird that makes the worm.",
    "Like punning, programming is a play on words.",
    'As Will Rogers would have said, "There is no such thing as a free variable."',
    "A LISP programmer knows the value of everything, but the cost of nothing.",
    "It is easier to change the specification to fit the program than vice versa.",
    "In seeking the unattainable, simplicity only gets in the way.",
    "In programming, as in everything else, to be in error is to be reborn.",
    "In computing, invariants are ephemeral.",
    'When we write programs that "learn", it turns out that we do and they don\'t.',
    "An adequate bootstrap is a contradiction in terms.",
    "It is the user who should parameterize procedures, not their creators.",
    "If your computer speaks English, it was probably made in Japan.",
    "A year spent in artificial intelligence is enough to make one believe in God.",
    "We are on the verge: Today our program proved Fermat's next-to-last theorem.",
    "Though the Chinese should adore APL, it's FORTRAN they put their money on.",
    "Computation has made the tree flower.",
    "Interfaces keep things tidy, but don't accelerate growth: Functions do.",
    "Don't have good ideas if you aren't willing to be responsible for them.",
    "Computers don't introduce order anywhere as much as they expose opportunities.",
    "In computing, the mean time to failure keeps getting shorter.",
    "In man-machine symbiosis, it is man who must adjust: The machines can't.",
    "One can't proceed from the informal to the formal by formal means.",
    "Purely applicative languages are poorly applicable.",
    "The proof of a system's value is its existence.",
    "You can't communicate complexity, only an awareness of it.",
    "The debate rages on: is PL/I Bachtrian or Dromedary?",
    "Whenever two programmers meet to criticize their programs, both are silent.",
    "Think of it! With VLSI we can pack 100 ENIACS in 1 sq. cm.",
    "Editing is a rewording activity.",
    "Why did the Roman Empire collapse? What is Latin for office automation?",
    "Computer Science is embarrassed by the computer.",
    "Within a computer natural language is unnatural.",
    "Most people find the concept of programming obvious, but the doing impossible.",
    "Programming is an unnatural act.",
]
