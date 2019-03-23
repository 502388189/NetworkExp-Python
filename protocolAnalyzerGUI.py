from tkinter import *
from tkinter.simpledialog import askstring

import AnalyzingEtherframe, AnalyzingIPDatagram,AnalyzingTCP

window = Tk()
window.title('GUI 协议分析器/编辑器')
window.geometry('700x300')
# 定义滚动条
resultText = Text(window, height=5)
resultText.place(x=50, y=200)


# MAC帧分析方法
def analysisEther():
    filter = askstring('输入筛选条件', '')
    # 点击cancel后不执行分析模块
    if filter is None:
        return
    resultlist = []
    # MAC帧分析模块
    AnalyzingEtherframe.catchPacket(filter, resultlist)
    for s in resultlist:
        resultText.insert('end', s)


def analysisIP():
    resultlist = []
    # IP分析模块
    AnalyzingIPDatagram.IPAnalyzer(resultlist)
    for s in resultlist:
        resultText.insert('end', s)
    return


def analysisTCP():
    resultlist = []
    AnalyzingTCP.TCPAnalyzer(resultlist)
    for s in resultlist:
        resultText.insert('end', s)
    return


macButton = \
    Button(window, text='MAC', font=('Arial', 12), width=10, height=1, command=lambda: analysisEther())
macButton.place(x=50, y=50)

ipButton = Button(window, text='IP', font=('Arial', 12), width=10, height=1, command=lambda: analysisIP())
ipButton.place(x=200, y=50)

tcpButton = Button(window, text='TCP', font=('Arial', 12), width=10, height=1, command=lambda: analysisTCP())
tcpButton.place(x=350, y=50)
window.mainloop()
