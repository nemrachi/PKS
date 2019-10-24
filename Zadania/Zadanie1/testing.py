import threading
import time

# answer = ''
# timers = 3
#
#
# def work(answer1):
#     t = threading.Timer(3, work)
#     t.start()
#     print("stackoverflow")
#     if answer1 is not '':
#         t.join()
#
#
# work(answer)
#
# while True:
#     answer = input("Input something: ")
#     print("\t", answer)


def wannaBeMain():
    sending = False

    def getInputeWhileKA():
        x = input("Enter")
        print("\t", x)
        nonlocal sending
        sending = True

    def keepAlive():
        while not sending:
            try:
                print('keepalive')
                time.sleep(4)
            except:
                print('error')

    inputThread = threading.Thread(target=getInputeWhileKA())
    inputThread.start()
    keepAlive()


wannaBeMain()