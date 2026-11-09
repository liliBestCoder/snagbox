"""Package only the Matplotlib resources used by Snagbox's headless PNG charts."""

from pathlib import Path

import matplotlib
from PyInstaller.compat import is_win
from PyInstaller.utils.hooks import collect_delvewheel_libs_directory


data_dir = Path(matplotlib.get_data_path())
datas = [(str(data_dir / "matplotlibrc"), "matplotlib/mpl-data")]
font_dir = data_dir / "fonts" / "ttf"
datas.extend(
    (str(font), "matplotlib/mpl-data/fonts/ttf")
    for font in [*font_dir.glob("DejaVuSans*.ttf"), font_dir / "LastResortHE-Regular.ttf"]
    if font.is_file()
)

binaries = []
if is_win:
    delvewheel_datas, delvewheel_binaries = collect_delvewheel_libs_directory("matplotlib")
    datas += delvewheel_datas
    binaries += delvewheel_binaries
