from swarmnat import __main__

__main__.main()


# 远程debug
# server端复制保存完整工程文件后，终端执行下面命令
#mamba activate pydbg311 && nohup python3 -m debugpy --listen 0.0.0.0:62678 --wait-for-client main.py &
