#!/usr/bin/python3

from PIL import Image, ImageDraw, ImageFont
import pdb
from time import sleep
import subprocess
import re
import cv2
import numpy as np
from selenium import webdriver
from selenium.common.exceptions import NoSuchElementException
from armory2.armory_main.included.utilities.color_display import (
    display_warning,
    display_new,
    display,
)
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
    success = False
    if highlight_text:
        
        for h, c in highlight_text:
            hl_data = []
            for i, t in enumerate(text_data):
                if h in t:
                    success = True
                    
                    if full_line:
                    
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
                    success = True
                    
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
    if highlight_text or box_text:
        return success
    else:
        return True

def run_command(cmd, leader="$ ", cols=100, lines=None, **kwargs):

    try:
        cmd_txt = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT).decode().replace('\r', '')
    except Exception as e:
        display_warning(f"Error running {cmd}: {e}")
        return False
    text_data = []
    # lengths = []
    for t in cmd_txt.split('\n'):
        if len(t) > cols:
            text_data += [t[i:i+cols] for i in range(0, len(t), cols)]
            # lengths.append(cols)
        else:
            text_data.append(t)
            # lengths.append(len(t)) 


    if lines and lines < len(text_data):
        search_text = [k[0] for k in kwargs.get('highlight_text', [])]
        search_text += [k[0] for k in kwargs.get('box_text', [])]
        if search_text:
            found_lines = []
            for s in search_text:
                found_lines += [i for i, k in enumerate(text_data) if s in k ]
            # pdb.set_trace()
            if not found_lines:
                found_lines = [0]
            mn = min(found_lines)
            mx = max(found_lines)
            rg = mx-mn+1
            
                
            if rg % 2:
                
                lower_offset = int((lines - rg + 1)/2)
                upper_offset = lower_offset
            else:
                lower_offset = int((lines - rg) / 2)
                upper_offset = lower_offset
            
            
            lower_line = mn - lower_offset
            upper_line = mx + upper_offset

            if lower_line < 0:
                lower_line = 0
                upper_line = lines
                
            elif upper_line > len(text_data):
                upper_line = len(text_data) - 1
                lower_line = len(text_data) - lines - 1
                
            txt = f"{leader}{cmd}| head -n {upper_line} | tail -n {lines}\n" + '\n'.join(text_data[lower_line:upper_line])  + '\n'

        else:
            txt = f"{leader}{cmd}| head -n {lines}\n" + '\n'.join(text_data[:lines]) + '\n'

    else:
        txt = f"{leader}{cmd}\n" + "\n".join(text_data)

    res = create_screenshot(txt, cols=cols, **kwargs)
    return res


def web_screenshot(url, save_path, draw_box = None, arrow = False, paddingh=10, paddingw=10, windowsize="800,600", cropsize=None):

    options = webdriver.ChromeOptions()
    options.add_argument('--ignore-certificate-errors')
    options.add_argument("--test-type")
    options.add_argument("--headless")
    options.add_argument(f"--window-size={windowsize}")
    options.add_argument('--no-sandbox')
    options.binary_location = "/usr/bin/chromium"
    driver = webdriver.Chrome(chrome_options=options)

    try:
        driver.get(url)
    except Exception as e:
        print(f"Error getting {url}: {e}")
        return False

    driver.save_screenshot(save_path)

    if not draw_box:
        return True

    success = False
    boxes = []
    center_points = []

    for items in draw_box:

        try:
            data = {}
            xpath = items[0]
            data['color'] = items[1]

            elem = driver.find_element_by_xpath(xpath)
            
            data['startx'] = elem.location['x'] - paddingw
            data['starty'] = elem.location['y'] - paddingh

            data['endx'] = elem.size['width'] + (paddingw * 2) + data['startx']
            data['endy'] = elem.size['height'] + (paddingh * 2) + data['starty']

            center_points.append([int(((data['endx'] - data['startx'])/2)+data['startx']), int(((data['endy'] - data['starty'])/2)+data['starty'])])
            boxes.append(data)
            success = True
        except NoSuchElementException:
            print(f"No results returned with {items[0]}")

    driver.close()
    img = Image.open(save_path)
    width, height = img.size

    for box in boxes:
        d = ImageDraw.Draw(img)
        for b in boxes:
        
        
            d.rectangle((b['startx'], b['starty'], b['endx'], b['endy']), fill=None, outline=b['color'], width=3)

    if arrow:
        na = np.array(img)

        for b in boxes:
            crds = get_arrow_coords(b['startx'], b['endx'], width, b['starty'], b['endy'], height)
            
            na = cv2.arrowedLine(na, crds[0], crds[1], b['color']+ (255,), 3)

        img = Image.fromarray(na)

    if cropsize:
        
        xs, ys = [int(c) for c in cropsize.split(',')]
        
        if not center_points:
            img = img.crop([0, 0, xs, ys])
        else:
            xc = int(sum([c[0] for c in center_points])/len(center_points))
            yc = int(sum([c[1] for c in center_points])/len(center_points))

            x_padding = int(xs/2)
            y_padding = int(ys/2)

            x1 = xc - x_padding
            x2 = x1 + xs
            y1 = yc - y_padding
            y2 = y1 + ys

            if x1 < 0:
                x1 = 0
                x2 = xs
            elif x2 > width:
                x1 = width - xs
                x2 = width
            if y1 < 0:
                y1 = 0
                y2 = ys
            elif y2 > height:
                y1 = height - y2
                y2 = height
            
            img = img.crop([x1, y1, x2, y2])

    img.save(save_path)
    return success


if __name__ == "__main__":


    # cmd = "sslscan https://depthsecurity.com | grep TLSv1 | sed 's/\x1b\[[0-9;]*m//g'"
    # run_command(cmd, box_text=[('enabled', (255,0,0))], highlight_text=[('TLSv1.2', (255,0,0)),('X-Frame-Options', (0,255,0))], arrow=True)

    url = 'https://depthsecurity.com'
    xpath = '//*[contains(text(), "If thre")]'
    color = (255,0,0)
    web_screenshot(url, '/tmp/depth2.png', draw_box=[(xpath, color)], arrow=True, paddingw=-100, paddingh=10, windowsize='800,800')



