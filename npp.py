#!/usr/bin/python3/
"""				
				this is a network programming and analysis course project 
		this is a program to scan open ports for a certain user entered domain based on a range of entered ports
		  using python multi-threading ,multiprocessing ,socket ,scapy networking library,and python's logging
		              	capabilities to log information about the scanned ports
          
				    by Ahmad Da'na #20121024 ,instructor : Dr.Ali Hadi  							"""
#ADD MORE PORTS RANGE CHECKING - TIME CLASS TO BUILD A TIME REQUIRED TO SCAN OBJECT

from threading import Thread,Lock
from socket import*
from socket import error as err
import time,sys,logging
from queue import Queue
from multiprocessing import Process
logging.basicConfig(filename='logger.log',level=logging.DEBUG)
from pprint import pprint
from timeit import timeit,default_timer

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


	global vLock, threadID,dom,Timeout, estimated

	clientSocket = socket(AF_INET,SOCK_STREAM)
	s=str(port)
	
	try: 				#handling socket exception :timeouts,connctionrefused

		vLock.acquire() 	# acquire the lock to modify global variables
		
		clientSocket.settimeout(Timeout)#setting time out limit for connection request to global timeout seconds
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

##################################        Coundown definition 		  #######################
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

if __name__ =="__main__": 			  #main 
	Timeout=0.2            #default timeout
	if len(sys.argv) <2 or sys.argv[1]=="-h": #check for input and print help message
			print ("""to use the port scanner use the following commands : 
	-h : for help  
	-i : to scan over a known ip adress ( will scan the every port if no port or port range was provided)
	-d xyz.abc : scan domain xyz.abc
	-o : scan over single port
	-t : to specifiy the timeout for scanning port (default is 0.2 seconds, maybe too fast for slow connections
	-r x y: scan over a range of ports from x to y
*scanning time is affected by target location , scanning an adress in your local network will be faster than scanning a web adress"""
				 )
			sys.exit()
	if '-t' in sys.argv :
		try :
			Timeout= float(sys.argv[sys.argv.index("-t")+1])
		except:
			print ("""make sure to provide a float or integer timeout after -t argument  Example :\n-t 0.4""")
			sys.exit()


	if "-i" in sys.argv and "-d" in sys.argv:
		print ("please enter a valid type of target domain or IP ")
		sys.exit()

	elif "-i" in sys.argv :
		try:
			site=dom=sys.argv[sys.argv.index('-i')+1]
			inet_aton(sys.argv[sys.argv.index('-i')+1])
		except:
			print ("please enter a valid IP format")
			sys.exit()
	elif "-d" in sys.argv :
		try:

			site=sys.argv[sys.argv.index('-d')+1]
			dom=gethostbyname(site)
		except :
			print ("""make sure to specifiy a valid website after -d ,example:
				-d google.com""")
			sys.exit()


	if "-r" not in sys.argv and '-o' not in sys.argv: 
		ports=list(range(1,(2**16)-1))
	if "-r" in sys.argv :            #checking range params
		i=sys.argv.index('-r')
		try:	
			por1=int(sys.argv[i+1])
			por=int(sys.argv[i+2])
			if (por<1 or por>65355) or(por1<1 or por1>65355):
				raise Exception
			else:

				if por1>por:
					ports =list(range(por,por1+1)) # create a list of ports to scan through	
				elif por>por1:
					ports =list(range(por1,por+1)) # create a list of ports to scan through
				else :
					ports=[por]
			
		except:
			print ("""please make sure you specifiy to initial port and final port right after -r 
				example :

				-r 1 100   ->this will scan port from to 100 inclusive	""")

			print("please enter an valid integer number between 1 to 65355\n")
			sys.exit()
	elif "-o" in sys.argv:
		i=sys.argv.index('-o')
		try:
			ports=[int(sys.argv[i+1])]
		except:
			print ("make sure you entered and integer port >=1 and less that 65356")
			sys.exit()
			
	q=Queue() # create a queue to store jobs
	
	
	print ("timeout =",Timeout)
	print("scanning target :",site ,' at ',dom)
	logging.info("scanning target : "+site +' at '+dom)
	OpenPorts = [] #this list will store the list of opened ports 
	vLock = Lock()
	iLock=Lock()
	threads=[]
	threadsList = [Thread(target=Scanner, args=(port,), daemon=True) for port in ports] #PRODUCING TASKS
	estimated=Dtime(len(threadsList)*Timeout)

	now=default_timer()
	  			
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
		
	
	
	print("\n Request Results for ",dom,":")
	for each in OpenPorts:
		
		try:
			print("server listening for ",getservbyport(each),"at port",each)
		except :
			print("unknown service running at port",each)
	p.terminate() #release the countdown process resources after finishing countdown  (instead of join , which will wait until end of the process even if the scanner scan every specified port , in example scanning lan hosts ports)
	
	pprint(OpenPorts)
	now2=default_timer()
	print ("actuall time ",int(now2-now),'seconds')
