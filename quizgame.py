print("welcome to my computer quiz!")

playing = input("Do you want to play? ")

if playing.lower() != "yes":
    quit()

print("okay! let's play :)")
score = 0

answer =  input("Who invented a computer? ")
if answer.lower() == "charles babbage":
    print("correct!")
    score += 1
else:    
    print("incorrect!")	


answer =  input("What was the first computer called? ")
if answer.upper() == "ENIAC":
    print("correct!")
    score += 1
else:    
    print("incorrect!")	


answer =  input("what does GPU stand for? ")
if answer.lower() == "graphics processing unit":
    print("correct!")
    score += 1
else:    
    print("incorrect!")	

answer =  input("what is RAM in full? ")
if answer.lower() == "random access memory":
    print("correct!")
    score += 1
else:    
    print("incorrect!")	

answer =  input("Who invented linux? ")
if answer.lower() == "linus torvalds":
    print("correct!")
    score +=1
else:    
    print("incorrect!")	

print("you got " +str(score) + " questions correct!")

print("you got " +str((score / 5) * 100) + "%.")







