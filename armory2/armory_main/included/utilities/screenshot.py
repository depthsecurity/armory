#!/usr/bin/python3

from PIL import Image, ImageDraw, ImageFont
import pdb
from time import sleep
from subprocess import check_output
import re
import cv2
import numpy as np

font = '/usr/share/fonts/liberation/LiberationMono-Regular.ttf'

font_height = 15
font_width = font_height * .6
border = 10
fnt = ImageFont.truetype(font, font_height)

def merge_txt(txt1, txt2):
    res = ''
    for i, t in enumerate(txt1):
        
        if txt2[i] != ' ':
            res += txt2[i]
        else:
            res += t
    
    return res

def get_arrow_coords(x1, x2, mx, y1, y2, my):
    y1 = int(y1)
    y2 = int(y2)
    midx1 = int((x2 + x1)/2)
    midy1 = int((y2 + y1)/2)

    midx = int(mx/2)
    midy = int(my/2)

    y_size = 90
    x_size = 90

    

    if midx1 < midx:
        if midy1 < midy:
            coords = ((x2 + x_size, y2 + y_size), (x2, y2))
        else:
            coords = ((x2 + x_size, y1 - y_size), (x2, y1))
    else:
        if midy1 < midy:
            coords = ((x1 - x_size, y2 + y_size), (x1, y2))
        else:
            coords = ((x1 - x_size, y1 - y_size), (x1, y1))
    return coords    
def create_screenshot(txt, cols=100, save_path=None, highlight_text=[], box_text='', arrow=False, full_line=False):

    lengths = []
    text_data = []

    for t in txt.split('\n'):
        if len(t) > cols:
            
            
            text_data += [t[i:i+cols] for i in range(0, len(t), cols)]
            
            lengths.append(cols)
        else:
            text_data.append(t)
            lengths.append(len(t)) 

    text = '\n'.join(text_data)

    length = int(sorted(lengths)[-1] * font_width + (2 * border))
    height = ((font_height+1)*len(text_data)) + (2 * border)

    img = Image.new('RGB', (length, height), color=(0,0,0))

    d = ImageDraw.Draw(img)

    d.text((border,border), text, font=fnt, fill=(255,255,255))
    
    if highlight_text:
        for h, c in highlight_text:
            hl_data = []
            for t in text_data:
                
                if full_line:
                    if h in t:
                        hl_data.append(t)
                    else:
                        hl_data.append('')
                else:
                    hl_data.append(h.join([' '*len(tx) for tx in t.split(h)]))
                
            hl_text = '\n'.join(hl_data)
            d = ImageDraw.Draw(img)

            d.text((border,border), hl_text, font=fnt, fill=c)

    if box_text:
        for h, c in box_text:
            offset_w = int(len(h)*font_width) + border
            offset_h = (font_height+1) + border

            coords = []
            for i, t in enumerate(text_data):
                if h in t:
                    if full_line:
                        f = 0
                        offset_w = int(len(t)*font_width) + border
                        x1 = int(f*font_width + border/2)
                        y1 = int(i*(font_height+2))+(border/2)
                        y2 = y1 + offset_h
                        x2 = x1 + offset_w
                        coords.append((x1, y1, x2, y2))
                    else:
                        finds = [m.start() for m in re.finditer(h, t)]
                        for f in finds:
                            x1 = int(f*font_width + border/2)
                            y1 = int(i*(font_height+2))+(border/2)
                            y2 = y1 + offset_h
                            x2 = x1 + offset_w
                            coords.append((x1, y1, x2, y2))

            d = ImageDraw.Draw(img)
            for c1 in coords:
                
                # print(c1)
                d.rectangle((c1[0], c1[1], c1[2], c1[3]), fill=None, outline=c, width=3)

            if arrow:
                na = np.array(img)

                for c1 in coords:
                    crds = get_arrow_coords(c1[0], c1[2], length, c1[1], c1[3], height)
                    # pdb.set_trace()
                    na = cv2.arrowedLine(na, crds[0], crds[1], c, 3)

                img = Image.fromarray(na)

    if save_path:
        img.save(save_path)
    else:
        img.show()

def run_command(cmd, leader="$ ", cols=100, **kwargs):

    cmd_txt = check_output(cmd, shell=True).decode().replace('\r', '')

    txt = f"{leader}{cmd}\n{cmd_txt}"

    create_screenshot(txt, cols=cols, **kwargs)



if __name__ == "__main__":


    cmd = "sslscan https://depthsecurity.com | grep TLSv1 | sed 's/\x1b\[[0-9;]*m//g'"
    run_command(cmd, box_text=[('enabled', (255,0,0))], highlight_text=[('TLSv1.2', (255,0,0)),('X-Frame-Options', (0,255,0))], arrow=True)


