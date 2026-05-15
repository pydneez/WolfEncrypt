# def mulInverse(a, m)
# Purpose: returns mulplicative inverse of a with respect to m using extended Euclid
# that is, mulInverse(a, m) returns d iff a*d = 1 mod m

# assumption: to ensure that mul. inverse exists, assume that gcd(a, m) = 1 
def mulInverse(a, m) : 
	m0 = m 
	y = 0
	x = 1

	if (m == 1) : 
		return 0

	while (a > 1) : 

		# q is quotient 
		q = a // m 

		t = m 

		# m is remainder now, process 
		# same as Euclid's algo 
		m = a % m 
		a = t 
		t = y 

		# Update x and y 
		y = x - q * y 
		x = t 


	# Make x positive 
	if (x < 0) : 
		x = x + m0 

	return x 


# Test
#a = 3
#m = 11
#print("Modular multiplicative inverse of", a, "modulo", m, "is", mulInverse(a, m))




