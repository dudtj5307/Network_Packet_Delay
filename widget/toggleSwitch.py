import tkinter as tk


class ToggleSwitch(tk.Canvas):
    def __init__(self, master=None, width=120, height=40,
                 bg_left="#4cd964", bg_right="#00BFFF", knob_color="white",
                 command=None, initial=False, *args, **kwargs):
        # Canvas의 배경은 부모의 배경색과 동일하게 설정
        tk.Canvas.__init__(self, master, width=width, height=height,
                           highlightthickness=0, bd=0, bg=master["bg"], *args, **kwargs)
        self.width = width
        self.height = height
        self.bg_left = bg_left
        self.bg_right = bg_right
        self.knob_color = knob_color
        self.command = command
        self.state = initial        # False: Routing, True: Bridging

        # 노브 크기 및 위치 설정 (위아래 여백 2픽셀)
        self.knob_diameter = height - 4
        self.knob_y = 2
        self.knob_off_x = 2
        self.knob_on_x = width - self.knob_diameter - 2

        # 배경: 둥근 직사각형 (polygon 방식)
        self.bg_rect = self.create_pill(0, 0, width, height,
                                                radius=height/2,
                                                fill=self.bg_right if self.state else self.bg_left,
                                                outline="")

        # 텍스트 생성: 왼쪽에는 "Routing", 오른쪽에는 "Bridging"
        self.left_text = self.create_text(self.width * 0.6, self.height / 2,
                                          text="Routing",
                                          font=("Helvetica", 8, "bold"))
        self.right_text = self.create_text(self.width * 0.4, self.height / 2,
                                           text="Bridging",
                                           font=("Helvetica", 8, "bold"))

        # 초기 상태에 따라 텍스트 표시: Routing일 때는 Routing 텍스트만 보이고 Bridging은 숨김, 반대의 경우도 마찬가지
        if self.state:
            self.itemconfigure(self.left_text, state="hidden")
            self.itemconfigure(self.right_text, state="normal")
        else:
            self.itemconfigure(self.left_text, state="normal")
            self.itemconfigure(self.right_text, state="hidden")

        # 노브: 원형 (초기 위치는 상태에 따라 결정)
        initial_x = self.knob_on_x if self.state else self.knob_off_x
        self.knob = self.create_oval(initial_x, self.knob_y,
                                     initial_x + self.knob_diameter,
                                     self.knob_y + self.knob_diameter,
                                     fill=self.knob_color, outline="")
        # 텍스트가 항상 노브 위에 보이도록 올림
        self.tag_raise(self.left_text)
        self.tag_raise(self.right_text)

        # 클릭 이벤트 바인딩 (Canvas, 배경, 노브, 텍스트 모두)
        self.bind("<Button-1>", self.toggle)
        self.tag_bind(self.bg_rect, "<Button-1>", self.toggle)
        self.tag_bind(self.knob, "<Button-1>", self.toggle)
        self.tag_bind(self.left_text, "<Button-1>", self.toggle)
        self.tag_bind(self.right_text, "<Button-1>", self.toggle)

        self.animating = False  # 애니메이션 진행 여부
        self.disabled = False

    def create_pill(self, x, y, w, h, radius, **kwargs):
        # Left Half-Circle: (x, y)에서 (x + 2*radius, y+h)
        left = self.create_oval(x, y, x + radius*2, y + radius*2, **kwargs)
        # Middle Rectangle
        middle = self.create_rectangle(x + radius, y, w - radius, y + h, **kwargs)
        # Right Half-Circle: (w-2*radius, y)에서 (w, y+h)
        right = self.create_oval(w - radius*2, y, w, y + h, **kwargs)

        tag = "pill_bg"
        self.addtag_withtag(tag, left)
        self.addtag_withtag(tag, middle)
        self.addtag_withtag(tag, right)
        return tag


    def toggle(self, event=None):
        # Ignore during Animation
        if self.animating or self.disabled:
            return
        # State Change (Routing <--> Bridging)
        self.state = not self.state

        self.animate_knob()

        # Update Background Color
        self.itemconfig(self.bg_rect, fill=self.bg_right if self.state else self.bg_left)

        # 텍스트 표시 업데이트: 활성 상태에 해당하는 텍스트만 보이게 설정
        if self.state:
            self.itemconfigure(self.left_text, state="hidden")
            self.itemconfigure(self.right_text, state="normal")
        else:
            self.itemconfigure(self.left_text, state="normal")
            self.itemconfigure(self.right_text, state="hidden")

        print(f"Changed Mode to {'\'Bridging\'' if self.state else '\'Routing\''}")

    def animate_knob(self):
        self.animating = True
        # Current Knob x-coordinate
        current_coords = self.coords(self.knob)
        current_x = current_coords[0]
        target_x = self.knob_on_x if self.state else self.knob_off_x
        step = 5  # 한 번에 이동할 픽셀 수

        if current_x < target_x:
            new_x = min(current_x + step, target_x)
        elif current_x > target_x:
            new_x = max(current_x - step, target_x)
        else:
            self.animating = False
            return

        dx = new_x - current_x
        self.move(self.knob, dx, 0)
        # 10ms 후에 다시 애니메이션 호출 (부드러운 움직임)
        self.after(10, self.animate_knob)

    def get_current_mode(self):
        return 'Bridging' if self.state else 'Routing'

    def disable(self):
        self.disabled = True

    def enable(self):
        self.disabled = False

# 사용 예시
if __name__ == "__main__":
    root = tk.Tk()
    root.title("iPhone 스타일 토글 스위치 (텍스트 표시)")
    root.config(bg="white")

    # ToggleSwitch 위젯 생성 (초기 상태: Routing)
    toggle = ToggleSwitch(root, width=80, height=20)
    toggle.pack(pady=20, padx=20)

    root.mainloop()