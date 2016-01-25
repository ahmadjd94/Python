#!/usr/bin/python3/
"""				
				this is a network programming and analysis course project 
		this is a program to scan open ports for a certain user entered domain based on a range of entered ports
		  using python multi-threading ,multiprocessing ,socket ,scapy networking library,and python's logging
		              	capabilities to log information about the scanned ports
          
				    by Ahmad Da'na #20121024 ,instructor : Dr.Ali Hadi  							"""
#ADD MORE PORTS RANGE CHECKING - TIME CLASS TO BUILD A TIME REQUIRED TO SCAN OBJECT
from scapy.all import *
from threading import Thread,Lock
from socket import*
from socket import error as err
import logging
from queue import Queue
from multiprocessing import Process
logging.basicConfig(filename='logger.log',level=logging.DEBUG)
import time
from pprint import pprint

######################### TIME CLASS DEFINITION ######################
"""class 'time' for estimating the time required to perform the scanning,overloaded function str() to perform direct printing of the time object and (-=) operator to perform unary subtraction operations"""
class Dtime :
	raw=0
	seconds=0
	minutes=0
	hours=0
	#INITIALIZER :
	
	def __init__(self,i):
		self.raw=i
		self.hours=int(i/3600)
		self.minutes=int((i%3600)/60)
		self.seconds=int(i%60)
		
	#GETTERS :
	def Min (self):			
		return self.minutes
		
	def Hour (self):
		return self.hours
		
	def Raw(self):
		return self.raw
		
	def Sec (self):
		return self.seconds
		
	#OVERLOADING SUBTRACTION OPERATOR :
	def __isub__(self,sec):
		new=Dtime(self.Raw()-sec)
		return (new)
	 #overloaded str :function need by the built in print function to print the object
	def __str__(self):
			return(str(self.hours)+" hours ,"+str(self.minutes)+" minutes ,"+str(self.seconds)+ ' seconds')			
		
########################## END OF TIME CLASS DEFINITION #########################


"""	Scanner function : takes a port as a parameter , checks if the server accept connection on the recieved port number
	if it does accept connections , it appends the port to the globally defined list 'OpenPorts'
	handles a few connection related excetions such as timeouts
"""

def Scanner(port):

	global vLock, threadID,dom
	clientSocket = socket(AF_INET,SOCK_STREAM)
	s=str(port)
	
	try: 				#handling socket exception :timeouts,connctionrefused
		vLock.acquire() 	# acquire the lock to modify global variables
		clientSocket.settimeout(.2)	#setting time out limit for connection request to 0.2 seconds
		clientSocket.connect((dom,port))
		clientSocket.shutdown(SHUT_RDWR)#force shutdown the connection socket /close function will keep the CLIENT waiting for a response, will only shut down the socket if the server sends an ACK
		logging.info("connection was successful to port "+s)
		print (port,"connection succeeded")
		OpenPorts.append(port) #append the port to the successfully scanned ports
		
		
	except ConnectionRefusedError:
		logging.info("connection refused at port "+s+"  ")
		#vLock.acquire()  this line was causing the program to hang , the thread will wait for the lock to be released forever
		
	except timeout: #performing actions to log file  if timeout exception occurs
       		logging.info("connection request timed out at port "+s )
       		
	except err:
		logging.info("socket error at port "+s )	
		
	except :
		logging.info("connection was unsuccessful to port "+s)
				
	finally:
		vLock.release() # release the lock of acquired lock
		
################################## function Scanner end of definition #######################

##coundown definition
"""countdown function : estimates the time required by the whole program to give results"""
def countdown ():
		
		global estimated #globally defined time object
		while estimated.Raw()>=1:
			if estimated.Raw()>=3600 and estimated.Raw()<7200: #if scanning would take more than hour
				time.sleep(600) #update timer every 10 minutes
				estimated-=600
				break;
			elif estimated.Raw()>=7200: #if scanning would take more than 2 hours
				time.sleep(1800) #update timer every half an hour
				estimated-=1800
				break;
			if estimated.Raw()>1 :
				print("estimated time",estimated)
			estimated-=5
			time.sleep(5)
			if estimated.Raw()<=0:
				break
######end of definition
		
if __name__ =="__main__":
	
	por=""
	while type(por)==str or type(por1)==str: 
		try:	
			por1=int(input("enter the initial ports range you would like to begin scanning with\n"))
			por=int(input("enter the final port you would like to finish  scanning with\n"))
			if (por<1 or por>65355) or(por1<1 or por1>65355):
				por=""
				raise Exception
		
				
		except:
			print("please enter an valid integer number between 1 to 65355\n")
			
	q=Queue() # create a queue to store jobs
	
	if por1>por:
		ports =list(range(por,por1+1)) # create a list of ports to scan through	
	elif por>por1:
		ports =list(range(por1,por+1)) # create a list of ports to scan through
	else :
		ports=[por]
		
	typ=(input('enter IP if you are scanning over known ip , Url for domain name'))	
	if typ=="ip"or"IP":
		site=dom=input("enter web site you would scan \n")
	else:
		site=input("enter web site you would scan \n")
		dom=gethostbyname(site) #r3turn the IP of the entered domain
	print("scanning target :",site ,' at ',dom)
	logging.info("scanning target : "+site +' at '+dom)
	OpenPorts = [] #this list will store the list of opened ports 
	vLock = Lock()
	threads=[]
	threadsList = [Thread(target=Scanner, args=(port,), daemon=True) for port in ports] #PRODUCING TASKS
	estimated=Dtime(len(threadsList)*.2)
	
	p=Process(target=countdown,daemon=True) #this is the countdown parallel process initializing
	p.start()   				#starting the parallel process
	
	print("estimated time",estimated ,' approximately to complete scanning through ' ,len(threadsList),' ports')
	logging.info("estimated time "+str(estimated) +' approximately to complete scanning through ' +str(len(threadsList))+' ports')	
	
	for thread in threadsList: 		#put each task in the threadsList in the queue
		q.put(thread)
	del(threadsList)
	
	#CONSUMER LOOP:
	while  q.empty()==False: 
		threads=[]
		n=0
		for n in range(0,100): # this would put 100 job in the lists to process (consuming 100 job at a time)
			if q.empty()==False:
				threads.append(q.get())
			else:
				break

		[thread.start() for thread in threads] #CONSUMING TASKS
		[thread.join() for thread in threads]	#releasing consumed tasks resources a
		
	Services = dict((scapy.all.TCP_SERVICES[k], k) for k in TCP_SERVICES.keys())# this will create a reversed dictionary containing a {service : port } mapping
	
	print("\n Request Results for ",dom,":")
	for each in OpenPorts:
		print("server is listening for ",Services[each],' connection at port ',each )
	
	p.join() #release the countdown process resources after finishing countdown

	pprint(OpenPorts)
