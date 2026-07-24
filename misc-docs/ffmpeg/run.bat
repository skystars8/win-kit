@echo off
echo ========================================
echo    YouTube Maximum Quality Converter
echo ========================================
echo.

if not exist "in.mp4" (
    echo ERROR: in.mp4 not found!
    echo Please put your video as "in.mp4" in this folder.
    pause
    exit
)

echo Converting in.mp4 to out.mp4 with best YouTube settings...
echo This may take a while depending on video length and your PC...

ffmpeg -i "in.mp4" ^
    -c:v libx264 ^
    -preset slower ^
    -crf 18 ^
    -pix_fmt yuv420p ^
    -vf "scale=iw:ih:flags=lanczos" ^
    -c:a aac ^
    -b:a 320k ^
    -movflags +faststart ^
    "out.mp4"

echo.
echo Done! Output saved as out.mp4
echo.
echo Recommended: Upload out.mp4 directly to YouTube.
pause