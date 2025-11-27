# Canon LBP2900/LBP3000 CAPT Driver

A reverse-engineered CUPS driver for Canon CAPT-based printers (LBP2900, LBP2900B, LBP3000).

## Features

- **5 Toner Density Levels**: Lightest, Light, Normal, Dark, Darkest
- **Toner Save Mode**: Reduce toner consumption
- **Multiple Media Types**: Plain Paper, Heavy Paper, Transparency, Envelope, etc.
- **11 Page Sizes**: A4, Letter, Legal, Executive, A5, B5, Envelopes, Index Card
- **Auto Paper Size Detection**: Automatically detects paper size from dimensions
- **Job Metadata**: Sends hostname, username, and document name to printer
- **LED Status**: Proper LED blinking for paper-out and other conditions
- **Communication Retry**: Automatic retry on USB communication errors
- **Graceful Job Cancellation**: Handles SIGTERM/SIGINT for clean cancellation

## Installation

### Arch Linux (AUR)

```bash
# Using yay
yay -S canon-lbp2900-capt

# Using paru
paru -S canon-lbp2900-capt

# Manual AUR installation
git clone https://aur.archlinux.org/canon-lbp2900-capt.git
cd canon-lbp2900-capt
makepkg -si
```

### From Source (All Distributions)

#### Prerequisites

- CUPS development libraries
- autoconf, automake
- GCC compiler

**Debian/Ubuntu:**
```bash
sudo apt install cups libcups2-dev autoconf automake build-essential
```

**Fedora/RHEL:**
```bash
sudo dnf install cups cups-devel autoconf automake gcc
```

**Arch Linux:**
```bash
sudo pacman -S cups autoconf automake base-devel
```

#### Build & Install

```bash
git clone https://github.com/gauravyad69/Canon-LBP2900B.git
cd Canon-LBP2900B

# Generate build system
aclocal
autoconf
automake --add-missing

# Configure and build
./configure
make

# Install (as root)
sudo make install

# Or manually install:
sudo cp src/rastertocapt /usr/lib/cups/filter/
sudo cp Canon-LBP-2900.ppd /usr/share/cups/model/

# Restart CUPS
sudo systemctl restart cups
```

### Add Printer

After installation:

1. Connect the printer via USB
2. Open CUPS web interface: http://localhost:631
3. Go to **Administration** → **Add Printer**
4. Select your Canon LBP2900 from the USB devices
5. Choose "Canon LBP2900 CAPT" as the driver
6. Configure print options as needed

Or via command line:
```bash
# List available devices
lpinfo -v | grep -i canon

# Add printer (replace usb://... with your device URI)
sudo lpadmin -p LBP2900 -E -v "usb://Canon/LBP2900?serial=..." -m Canon-LBP-2900.ppd
```

## Configuration Options

Available through CUPS print dialog or `lpoptions`:

| Option | Values | Description |
|--------|--------|-------------|
| TonerDensity | 1-5 | Toner density (1=Lightest, 5=Darkest) |
| TonerSave | Off, On | Enable toner saving mode |
| MediaType | Plain, Heavy, HeavyH, PlainL, Transparency, Envelope | Paper type |
| PageSize | A4, Letter, Legal, Executive, A5, B5, Envelope#10, EnvelopeC5, EnvelopeDL, EnvelopeMonarch, IndexCard | Paper size |

Example:
```bash
lp -d LBP2900 -o TonerDensity=3 -o MediaType=Plain document.pdf
```

## Troubleshooting

### Printer not detected
```bash
# Check USB connection
lsusb | grep Canon
# Should show: 04a9:2676 Canon, Inc. LBP2900

# Check CUPS status
sudo systemctl status cups
```

### Permission issues
```bash
# Add user to lp group
sudo usermod -aG lp $USER
# Log out and back in
```

### Debug printing
```bash
# Enable CUPS debug logging
sudo cupsctl --debug-logging

# View logs
tail -f /var/log/cups/error_log
```

## Protocol Documentation

See the [SPECS](SPECS) file for reverse-engineered protocol documentation.

## License

GPL-2.0-or-later

## Credits

- Original reverse engineering by Alexey Galakhov
- Additional features by Gaurav Yadav
- Based on USB traffic analysis of the official Canon Windows driver
