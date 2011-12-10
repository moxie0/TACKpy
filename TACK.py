#! /usr/bin/env python

# TACK tool - written 2011 by Trevor Perrin, hereby placed in public domain
# Includes public domain code from:
#   Peter Pearson (Number theory, Elliptic curve, ECDSA)
#   Bram Cohen (Rijndael)


################ NUMBER THEORY ###
#! /usr/bin/env python
#
# Provide some simple capabilities from number theory.
#
# Version of 2008.11.14.
#
# Written in 2005 and 2006 by Peter Pearson and placed in the public domain.
# Revision history:
#   2008.11.14: Use pow( base, exponent, modulus ) for modular_exp.
#               Make gcd and lcm accept arbitrarly many arguments.



import math
import types


class Error( Exception ):
  """Base class for exceptions in this module."""
  pass

class SquareRootError( Error ):
  pass

class NegativeExponentError( Error ):
  pass


def modular_exp( base, exponent, modulus ):
  "Raise base to exponent, reducing by modulus"
  if exponent < 0:
    raise NegativeExponentError( "Negative exponents (%d) not allowed" \
                                 % exponent )
  return pow( base, exponent, modulus )
#   result = 1L
#   x = exponent
#   b = base + 0L
#   while x > 0:
#     if x % 2 > 0: result = (result * b) % modulus
#     x = x / 2
#     b = ( b * b ) % modulus
#   return result


def polynomial_reduce_mod( poly, polymod, p ):
  """Reduce poly by polymod, integer arithmetic modulo p.

  Polynomials are represented as lists of coefficients
  of increasing powers of x."""

  # This module has been tested only by extensive use
  # in calculating modular square roots.

  # Just to make this easy, require a monic polynomial:
  assert polymod[-1] == 1

  assert len( polymod ) > 1

  while len( poly ) >= len( polymod ):
    if poly[-1] != 0:
      for i in range( 2, len( polymod ) + 1 ):
        poly[-i] = ( poly[-i] - poly[-1] * polymod[-i] ) % p
    poly = poly[0:-1]

  return poly



def polynomial_multiply_mod( m1, m2, polymod, p ):
  """Polynomial multiplication modulo a polynomial over ints mod p.

  Polynomials are represented as lists of coefficients
  of increasing powers of x."""

  # This is just a seat-of-the-pants implementation.

  # This module has been tested only by extensive use
  # in calculating modular square roots.

  # Initialize the product to zero:

  prod = ( len( m1 ) + len( m2 ) - 1 ) * [0]

  # Add together all the cross-terms:

  for i in range( len( m1 ) ):
    for j in range( len( m2 ) ):
      prod[i+j] = ( prod[i+j] + m1[i] * m2[j] ) % p

  return polynomial_reduce_mod( prod, polymod, p )

  

  
def polynomial_exp_mod( base, exponent, polymod, p ):
  """Polynomial exponentiation modulo a polynomial over ints mod p.

  Polynomials are represented as lists of coefficients
  of increasing powers of x."""

  # Based on the Handbook of Applied Cryptography, algorithm 2.227.

  # This module has been tested only by extensive use
  # in calculating modular square roots.

  assert exponent < p

  if exponent == 0: return [ 1 ]

  G = base
  k = exponent
  if k%2 == 1: s = G
  else:        s = [ 1 ]

  while k > 1:
    k = k // 2
    G = polynomial_multiply_mod( G, G, polymod, p )
    if k%2 == 1: s = polynomial_multiply_mod( G, s, polymod, p )

  return s



def jacobi( a, n ):
  """Jacobi symbol"""

  # Based on the Handbook of Applied Cryptography (HAC), algorithm 2.149.

  # This function has been tested by comparison with a small
  # table printed in HAC, and by extensive use in calculating
  # modular square roots.

  assert n >= 3
  assert n%2 == 1
  a = a % n
  if a == 0: return 0
  if a == 1: return 1
  a1, e = a, 0
  while a1%2 == 0:
    a1, e = a1//2, e+1
  if e%2 == 0 or n%8 == 1 or n%8 == 7: s = 1
  else: s = -1
  if a1 == 1: return s
  if n%4 == 3 and a1%4 == 3: s = -s
  return s * jacobi( n % a1, a1 )
  



def square_root_mod_prime( a, p ):
  """Modular square root of a, mod p, p prime."""

  # Based on the Handbook of Applied Cryptography, algorithms 3.34 to 3.39.

  # This module has been tested for all values in [0,p-1] for
  # every prime p from 3 to 1229.

  assert 0 <= a < p
  assert 1 < p

  if a == 0: return 0
  if p == 2: return a
  
  jac = jacobi( a, p )
  if jac == -1: raise SquareRootError( "%d has no square root modulo %d" \
                                       % ( a, p ) )

  if p % 4 == 3: return modular_exp( a, (p+1)//4, p )

  if p % 8 == 5:
    d = modular_exp( a, (p-1)//4, p )
    if d == 1: return modular_exp( a, (p+3)//8, p )
    if d == p-1: return ( 2 * a * modular_exp( 4*a, (p-5)//8, p ) ) % p
    raise RuntimeError("Shouldn't get here.")

  for b in range( 2, p ):
    if jacobi( b*b-4*a, p ) == -1:
      f = ( a, -b, 1 )
      ff = polynomial_exp_mod( ( 0, 1 ), (p+1)//2, f, p )
      assert ff[1] == 0
      return ff[0]
  raise RuntimeError("No b found.")



def inverse_mod( a, m ):
  """Inverse of a mod m."""

  if a < 0 or m <= a: a = a % m

  # From Ferguson and Schneier, roughly:

  c, d = a, m
  uc, vc, ud, vd = 1, 0, 0, 1
  while c != 0:
    q, c, d = divmod( d, c ) + ( c, )
    uc, vc, ud, vd = ud - q*uc, vd - q*vc, uc, vc

  # At this point, d is the GCD, and ud*a+vd*m = d.
  # If d == 1, this means that ud is a inverse.

  assert d == 1
  if ud > 0: return ud
  else: return ud + m


def gcd2(a, b):
  """Greatest common divisor using Euclid's algorithm."""
  while a:
    a, b = b%a, a
  return b


def gcd( *a ):
  """Greatest common divisor.

  Usage: gcd( [ 2, 4, 6 ] )
  or:    gcd( 2, 4, 6 )
  """

  if len( a ) > 1: return reduce( gcd2, a )
  if hasattr( a[0], "__iter__" ): return reduce( gcd2, a[0] )
  return a[0]


def lcm2(a,b):
  """Least common multiple of two integers."""

  return (a*b)//gcd(a,b)


def lcm( *a ):
  """Least common multiple.

  Usage: lcm( [ 3, 4, 5 ] )
  or:    lcm( 3, 4, 5 )
  """

  if len( a ) > 1: return reduce( lcm2, a )
  if hasattr( a[0], "__iter__" ): return reduce( lcm2, a[0] )
  return a[0]



def factorization( n ):
  """Decompose n into a list of (prime,exponent) pairs."""

  assert isinstance( n, types.IntType ) or isinstance( n, types.LongType )

  if n < 2: return []

  result = []
  d = 2

  # Test the small primes:

  for d in smallprimes:
    if d > n: break
    q, r = divmod( n, d )
    if r == 0:
      count = 1
      while d <= n:
        n = q
        q, r = divmod( n, d )
        if r != 0: break
        count = count + 1
      result.append( ( d, count ) )

  # If n is still greater than the last of our small primes,
  # it may require further work:

  if n > smallprimes[-1]:
    if is_prime( n ):   # If what's left is prime, it's easy:
      result.append( ( n, 1 ) )
    else:               # Ugh. Search stupidly for a divisor:
      d = smallprimes[-1]
      while 1:
        d = d + 2               # Try the next divisor.
        q, r = divmod( n, d )
        if q < d: break         # n < d*d means we're done, n = 1 or prime.
        if r == 0:              # d divides n. How many times?
          count = 1
          n = q
          while d <= n:                 # As long as d might still divide n,
            q, r = divmod( n, d )       # see if it does.
            if r != 0: break
            n = q                       # It does. Reduce n, increase count.
            count = count + 1
          result.append( ( d, count ) )
      if n > 1: result.append( ( n, 1 ) )
        
  return result



def phi( n ):
  """Return the Euler totient function of n."""

  assert isinstance( n, types.IntType ) or isinstance( n, types.LongType )

  if n < 3: return 1

  result = 1
  ff = factorization( n )
  for f in ff:
    e = f[1]
    if e > 1:
      result = result * f[0] ** (e-1) * ( f[0] - 1 )
    else:
      result = result * ( f[0] - 1 )
  return result


def carmichael( n ):
  """Return Carmichael function of n.

  Carmichael(n) is the smallest integer x such that
  m**x = 1 mod n for all m relatively prime to n.
  """

  return carmichael_of_factorized( factorization( n ) )


def carmichael_of_factorized( f_list ):
  """Return the Carmichael function of a number that is
  represented as a list of (prime,exponent) pairs.
  """

  if len( f_list ) < 1: return 1

  result = carmichael_of_ppower( f_list[0] )
  for i in range( 1, len( f_list ) ):
    result = lcm( result, carmichael_of_ppower( f_list[i] ) )

  return result

def carmichael_of_ppower( pp ):
  """Carmichael function of the given power of the given prime.
  """

  p, a = pp
  if p == 2 and a > 2: return 2**(a-2)
  else: return (p-1) * p**(a-1)



def order_mod( x, m ):
  """Return the order of x in the multiplicative group mod m.
  """

  # Warning: this implementation is not very clever, and will
  # take a long time if m is very large.

  if m <= 1: return 0

  assert gcd( x, m ) == 1

  z = x
  result = 1
  while z != 1:
    z = ( z * x ) % m
    result = result + 1
  return result


def largest_factor_relatively_prime( a, b ):
  """Return the largest factor of a relatively prime to b.
  """

  while 1:
    d = gcd( a, b )
    if d <= 1: break
    b = d
    while 1:
      q, r = divmod( a, d )
      if r > 0:
        break
      a = q
  return a


def kinda_order_mod( x, m ):
  """Return the order of x in the multiplicative group mod m',
  where m' is the largest factor of m relatively prime to x.
  """

  return order_mod( x, largest_factor_relatively_prime( m, x ) )


def is_prime( n ):
  """Return True if x is prime, False otherwise.

  We use the Miller-Rabin test, as given in Menezes et al. p. 138.
  This test is not exact: there are composite values n for which
  it returns True.

  In testing the odd numbers from 10000001 to 19999999,
  about 66 composites got past the first test,
  5 got past the second test, and none got past the third.
  Since factors of 2, 3, 5, 7, and 11 were detected during
  preliminary screening, the number of numbers tested by
  Miller-Rabin was (19999999 - 10000001)*(2/3)*(4/5)*(6/7)
  = 4.57 million.
  """
  
  # (This is used to study the risk of false positives:)
  global miller_rabin_test_count

  miller_rabin_test_count = 0
  
  if n <= smallprimes[-1]:
    if n in smallprimes: return True
    else: return False

  if gcd( n, 2*3*5*7*11 ) != 1: return False

  # Choose a number of iterations sufficient to reduce the
  # probability of accepting a composite below 2**-80
  # (from Menezes et al. Table 4.4):

  t = 40
  n_bits = 1 + int( math.log( n, 2 ) )
  for k, tt in ( ( 100, 27 ),
                 ( 150, 18 ),
                 ( 200, 15 ),
                 ( 250, 12 ),
                 ( 300,  9 ),
                 ( 350,  8 ),
                 ( 400,  7 ),
                 ( 450,  6 ),
                 ( 550,  5 ),
                 ( 650,  4 ),
                 ( 850,  3 ),
                 ( 1300, 2 ),
                 ):
    if n_bits < k: break
    t = tt

  # Run the test t times:

  s = 0
  r = n - 1
  while ( r % 2 ) == 0:
    s = s + 1
    r = r // 2
  for i in range( t ):
    a = smallprimes[ i ]
    y = modular_exp( a, r, n )
    if y != 1 and y != n-1:
      j = 1
      while j <= s - 1 and y != n - 1:
        y = modular_exp( y, 2, n )
        if y == 1:
          miller_rabin_test_count = i + 1
          return False
        j = j + 1
      if y != n-1:
        miller_rabin_test_count = i + 1
        return False
  return True


def next_prime( starting_value ):
  "Return the smallest prime larger than the starting value."

  if starting_value < 2: return 2
  result = ( starting_value + 1 ) | 1
  while not is_prime( result ): result = result + 2
  return result


smallprimes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41,
               43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97,
               101, 103, 107, 109, 113, 127, 131, 137, 139, 149,
               151, 157, 163, 167, 173, 179, 181, 191, 193, 197,
               199, 211, 223, 227, 229, 233, 239, 241, 251, 257,
               263, 269, 271, 277, 281, 283, 293, 307, 311, 313,
               317, 331, 337, 347, 349, 353, 359, 367, 373, 379,
               383, 389, 397, 401, 409, 419, 421, 431, 433, 439,
               443, 449, 457, 461, 463, 467, 479, 487, 491, 499,
               503, 509, 521, 523, 541, 547, 557, 563, 569, 571,
               577, 587, 593, 599, 601, 607, 613, 617, 619, 631,
               641, 643, 647, 653, 659, 661, 673, 677, 683, 691,
               701, 709, 719, 727, 733, 739, 743, 751, 757, 761,
               769, 773, 787, 797, 809, 811, 821, 823, 827, 829,
               839, 853, 857, 859, 863, 877, 881, 883, 887, 907,
               911, 919, 929, 937, 941, 947, 953, 967, 971, 977,
               983, 991, 997, 1009, 1013, 1019, 1021, 1031, 1033,
               1039, 1049, 1051, 1061, 1063, 1069, 1087, 1091, 1093,
               1097, 1103, 1109, 1117, 1123, 1129, 1151, 1153, 1163,
               1171, 1181, 1187, 1193, 1201, 1213, 1217, 1223, 1229]


################ ELLIPTIC CURVE ###

#! /usr/bin/env python
#
# Implementation of elliptic curves, for cryptographic applications.
#
# This module doesn't provide any way to choose a random elliptic
# curve, nor to verify that an elliptic curve was chosen randomly,
# because one can simply use NIST's standard curves.
#
# Notes from X9.62-1998 (draft):
#   Nomenclature:
#     - Q is a public key.
#     The "Elliptic Curve Domain Parameters" include:
#     - q is the "field size", which in our case equals p.
#     - p is a big prime.
#     - G is a point of prime order (5.1.1.1).
#     - n is the order of G (5.1.1.1).
#   Public-key validation (5.2.2):
#     - Verify that Q is not the point at infinity.
#     - Verify that X_Q and Y_Q are in [0,p-1].
#     - Verify that Q is on the curve.
#     - Verify that nQ is the point at infinity.
#   Signature generation (5.3):
#     - Pick random k from [1,n-1].
#   Signature checking (5.4.2):
#     - Verify that r and s are in [1,n-1].
#
# Version of 2008.11.25.
#
# Revision history:
#    2005.12.31 - Initial version.
#    2008.11.25 - Change CurveFp.is_on to contains_point.
#
# Written in 2005 by Peter Pearson and placed in the public domain.

class CurveFp( object ):
  """Elliptic Curve over the field of integers modulo a prime."""
  def __init__( self, p, a, b ):
    """The curve of points satisfying y^2 = x^3 + a*x + b (mod p)."""
    self.__p = p
    self.__a = a
    self.__b = b

  def p( self ):
    return self.__p

  def a( self ):
    return self.__a

  def b( self ):
    return self.__b

  def contains_point( self, x, y ):
    """Is the point (x,y) on this curve?"""
    return ( y * y - ( x * x * x + self.__a * x + self.__b ) ) % self.__p == 0



class Point( object ):
  """A point on an elliptic curve. Altering x and y is forbidding,
     but they can be read by the x() and y() methods."""
  def __init__( self, curve, x, y, order = None ):
    """curve, x, y, order; order (optional) is the order of this point."""
    self.__curve = curve
    self.__x = x
    self.__y = y
    self.__order = order
    # self.curve is allowed to be None only for INFINITY:
    if self.__curve: assert self.__curve.contains_point( x, y )
    if order: assert self * order == INFINITY
 
  def __cmp__( self, other ):
    """Return 0 if the points are identical, 1 otherwise."""
    if self.__curve == other.__curve \
       and self.__x == other.__x \
       and self.__y == other.__y:
      return 0
    else:
      return 1

  def __add__( self, other ):
    """Add one point to another point."""
    
    # X9.62 B.3:

    if other == INFINITY: return self
    if self == INFINITY: return other
    assert self.__curve == other.__curve
    if self.__x == other.__x:
      if ( self.__y + other.__y ) % self.__curve.p() == 0:
        return INFINITY
      else:
        return self.double()

    p = self.__curve.p()

    l = ( ( other.__y - self.__y ) * \
          inverse_mod( other.__x - self.__x, p ) ) % p

    x3 = ( l * l - self.__x - other.__x ) % p
    y3 = ( l * ( self.__x - x3 ) - self.__y ) % p
    
    return Point( self.__curve, x3, y3 )

  def __mul__( self, other ):
    """Multiply a point by an integer."""

    def leftmost_bit( x ):
      assert x > 0
      result = 1
      while result <= x: result = 2 * result
      return result // 2

    e = other
    if self.__order: e = e % self.__order
    if e == 0: return INFINITY
    if self == INFINITY: return INFINITY
    assert e > 0

    # From X9.62 D.3.2:

    e3 = 3 * e
    negative_self = Point( self.__curve, self.__x, -self.__y, self.__order )
    i = leftmost_bit( e3 ) // 2
    result = self
    # print "Multiplying %s by %d (e3 = %d):" % ( self, other, e3 )
    while i > 1:
      result = result.double()
      if ( e3 & i ) != 0 and ( e & i ) == 0: result = result + self
      if ( e3 & i ) == 0 and ( e & i ) != 0: result = result + negative_self
      # print ". . . i = %d, result = %s" % ( i, result )
      i = i // 2

    return result

  def __rmul__( self, other ):
    """Multiply a point by an integer."""
    
    return self * other

  def __str__( self ):
    if self == INFINITY: return "infinity"
    return "(%d,%d)" % ( self.__x, self.__y )

  def double( self ):
    """Return a new point that is twice the old."""

    # X9.62 B.3:

    p = self.__curve.p()
    a = self.__curve.a()

    l = ( ( 3 * self.__x * self.__x + a ) * \
          inverse_mod( 2 * self.__y, p ) ) % p

    x3 = ( l * l - 2 * self.__x ) % p
    y3 = ( l * ( self.__x - x3 ) - self.__y ) % p
    
    return Point( self.__curve, x3, y3 )

  def x( self ):
    return self.__x

  def y( self ):
    return self.__y

  def curve( self ):
    return self.__curve
  
  def order( self ):
    return self.__order


# This one point is the Point At Infinity for all purposes:
INFINITY = Point( None, None, None )  


################ ECDSA ###
#! /usr/bin/env python
"""
Implementation of Elliptic-Curve Digital Signatures.

Classes and methods for elliptic-curve signatures:
private keys, public keys, signatures,
NIST prime-modulus curves with modulus lengths of
192, 224, 256, 384, and 521 bits.

Example:

  # (In real-life applications, you would probably want to
  # protect against defects in SystemRandom.)
  from random import SystemRandom
  randrange = SystemRandom().randrange

  # Generate a public/private key pair using the NIST Curve P-192:

  g = generator_192
  n = g.order()
  secret = randrange( 1, n )
  pubkey = Public_key( g, g * secret )
  privkey = Private_key( pubkey, secret )

  # Signing a hash value:
 
  hash = randrange( 1, n )
  signature = privkey.sign( hash, randrange( 1, n ) )

  # Verifying a signature for a hash value:

  if pubkey.verifies( hash, signature ):
    print "Demo verification succeeded."
  else:
    print "*** Demo verification failed."

  # Verification fails if the hash value is modified:

  if pubkey.verifies( hash-1, signature ):
    print "**** Demo verification failed to reject tampered hash."
  else:
    print "Demo verification correctly rejected tampered hash."

Version of 2009.05.16.

Revision history:
      2005.12.31 - Initial version.
      2008.11.25 - Substantial revisions introducing new classes.
      2009.05.16 - Warn against using random.randrange in real applications.
      2009.05.17 - Use random.SystemRandom by default.

Written in 2005 by Peter Pearson and placed in the public domain.
"""

class Signature( object ):
  """ECDSA signature.
  """
  def __init__( self, r, s ):
    self.r = r
    self.s = s



class Public_key( object ):
  """Public key for ECDSA.
  """

  def __init__( self, generator, point ):
    """generator is the Point that generates the group,
    point is the Point that defines the public key.
    """
    
    self.curve = generator.curve()
    self.generator = generator
    self.point = point
    n = generator.order()
    if not n:
      raise RuntimeError("Generator point must have order.")
    if not n * point == INFINITY:
      raise RuntimeError("Generator point order is bad.")
    if point.x() < 0 or n <= point.x() or point.y() < 0 or n <= point.y():
      raise RuntimeError("Generator point has x or y out of range.")


  def verifies( self, hash, signature ):
    """Verify that signature is a valid signature of hash.
    Return True if the signature is valid.
    """

    # From X9.62 J.3.1.

    G = self.generator
    n = G.order()
    r = signature.r
    s = signature.s
    if r < 1 or r > n-1: return False
    if s < 1 or s > n-1: return False
    c = inverse_mod( s, n )
    u1 = ( hash * c ) % n
    u2 = ( r * c ) % n
    xy = u1 * G + u2 * self.point
    v = xy.x() % n
    return v == r
    


class Private_key( object ):
  """Private key for ECDSA.
  """

  def __init__( self, public_key, secret_multiplier ):
    """public_key is of class Public_key;
    secret_multiplier is a large integer.
    """
    
    self.public_key = public_key
    self.secret_multiplier = secret_multiplier

  def sign( self, hash, random_k ):
    """Return a signature for the provided hash, using the provided
    random nonce.  It is absolutely vital that random_k be an unpredictable
    number in the range [1, self.public_key.point.order()-1].  If
    an attacker can guess random_k, he can compute our private key from a
    single signature.  Also, if an attacker knows a few high-order
    bits (or a few low-order bits) of random_k, he can compute our private
    key from many signatures.  The generation of nonces with adequate
    cryptographic strength is very difficult and far beyond the scope
    of this comment.

    May raise RuntimeError, in which case retrying with a new
    random value k is in order.
    """

    G = self.public_key.generator
    n = G.order()
    k = random_k % n
    p1 = k * G
    r = p1.x()
    if r == 0: raise RuntimeError("amazingly unlucky random number r")
    s = ( inverse_mod( k, n ) * \
          ( hash + ( self.secret_multiplier * r ) % n ) ) % n
    if s == 0: raise RuntimeError("amazingly unlucky random number s")
    return Signature( r, s )



def int_to_string( x ):
  """Convert integer x into a string of bytes, as per X9.62."""
  assert x >= 0
  if x == 0: return chr(0)
  result = ""
  while x > 0:
    q, r = divmod( x, 256 )
    result = chr( r ) + result
    x = q
  return result


def string_to_int( s ):
  """Convert a string of bytes into an integer, as per X9.62."""
  result = 0
  for c in s: result = 256 * result + ord( c )
  return result


def digest_integer( m ):
  """Convert an integer into a string of bytes, compute
     its SHA-1 hash, and convert the result to an integer."""
  #
  # I don't expect this function to be used much. I wrote
  # it in order to be able to duplicate the examples
  # in ECDSAVS.
  #
  import sha
  return string_to_int( sha.new( int_to_string( m ) ).digest() )


def point_is_valid( generator, x, y ):
  """Is (x,y) a valid public key based on the specified generator?"""

  # These are the tests specified in X9.62.

  n = generator.order()
  curve = generator.curve()
  if x < 0 or n <= x or y < 0 or n <= y:
    return False
  if not curve.contains_point( x, y ):
    return False
  if not n*Point( curve, x, y ) == \
     INFINITY:
    return False
  return True


# NIST Curve P-256:
_p = 115792089210356248762697446949407573530086143415290314195533631308867097853951
_r = 115792089210356248762697446949407573529996955224135760342422259061068512044369
# s = 0xc49d360886e704936a6678e1139d26b7819f7e90L
# c = 0x7efba1662985be9403cb055c75d4f7e0ce8d84a9c5114abcaf3177680104fa0dL
_b = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
_Gx = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296
_Gy = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5

curve_256 = CurveFp( _p, -3, _b )
generator_256 = Point( curve_256, _Gx, _Gy, _r )



################ RIJNDAEL ###
"""
A pure python (slow) implementation of rijndael with a decent interface

To include -

from rijndael import rijndael

To do a key setup -

r = rijndael(key, block_size = 16)

key must be a string of length 16, 24, or 32
blocksize must be 16, 24, or 32. Default is 16

To use -

ciphertext = r.encrypt(plaintext)
plaintext = r.decrypt(ciphertext)

If any strings are of the wrong length a ValueError is thrown
"""

# ported from the Java reference code by Bram Cohen, bram@gawth.com, April 2001
# this code is public domain, unless someone makes
# an intellectual property claim against the reference
# code, in which case it can be made public domain by
# deleting all the comments and renaming all the variables

import copy
import string



#TREV 2011 - is this still needed? seems not
#-----------------------
#TREV - ADDED BECAUSE THERE'S WARNINGS ABOUT INT OVERFLOW BEHAVIOR CHANGING IN
#2.4.....
#import os
#if os.name != "java":
#    import exceptions
#    if hasattr(exceptions, "FutureWarning"):
#        import warnings
#        warnings.filterwarnings("ignore", category=FutureWarning, append=1)
#-----------------------



shifts = [[[0, 0], [1, 3], [2, 2], [3, 1]],
          [[0, 0], [1, 5], [2, 4], [3, 3]],
          [[0, 0], [1, 7], [3, 5], [4, 4]]]

# [keysize][block_size]
num_rounds = {16: {16: 10, 24: 12, 32: 14}, 
24: {16: 12, 24: 12, 32: 14}, 32: {16: 14, 24: 14, 32: 14}}

A = [[1, 1, 1, 1, 1, 0, 0, 0],
     [0, 1, 1, 1, 1, 1, 0, 0],
     [0, 0, 1, 1, 1, 1, 1, 0],
     [0, 0, 0, 1, 1, 1, 1, 1],
     [1, 0, 0, 0, 1, 1, 1, 1],
     [1, 1, 0, 0, 0, 1, 1, 1],
     [1, 1, 1, 0, 0, 0, 1, 1],
     [1, 1, 1, 1, 0, 0, 0, 1]]

# produce log and alog tables, needed for multiplying in the
# field GF(2^m) (generator = 3)
alog = [1]
for i in range(255):
    j = (alog[-1] << 1) ^ alog[-1]
    if j & 0x100 != 0:
        j ^= 0x11B
    alog.append(j)

log = [0] * 256
for i in range(1, 255):
    log[alog[i]] = i

# multiply two elements of GF(2^m)
def mul(a, b):
    if a == 0 or b == 0:
        return 0
    return alog[(log[a & 0xFF] + log[b & 0xFF]) % 255]

# substitution box based on F^{-1}(x)
box = [[0] * 8 for i in range(256)]
box[1][7] = 1
for i in range(2, 256):
    j = alog[255 - log[i]]
    for t in range(8):
        box[i][t] = (j >> (7 - t)) & 0x01

B = [0, 1, 1, 0, 0, 0, 1, 1]

# affine transform:  box[i] <- B + A*box[i]
cox = [[0] * 8 for i in range(256)]
for i in range(256):
    for t in range(8):
        cox[i][t] = B[t]
        for j in range(8):
            cox[i][t] ^= A[t][j] * box[i][j]

# S-boxes and inverse S-boxes
S =  [0] * 256
Si = [0] * 256
for i in range(256):
    S[i] = cox[i][0] << 7
    for t in range(1, 8):
        S[i] ^= cox[i][t] << (7-t)
    Si[S[i] & 0xFF] = i

# T-boxes
G = [[2, 1, 1, 3],
    [3, 2, 1, 1],
    [1, 3, 2, 1],
    [1, 1, 3, 2]]

AA = [[0] * 8 for i in range(4)]

for i in range(4):
    for j in range(4):
        AA[i][j] = G[i][j]
        AA[i][i+4] = 1

for i in range(4):
    pivot = AA[i][i]
    if pivot == 0:
        t = i + 1
        while AA[t][i] == 0 and t < 4:
            t += 1
            assert t != 4, 'G matrix must be invertible'
            for j in range(8):
                AA[i][j], AA[t][j] = AA[t][j], AA[i][j]
            pivot = AA[i][i]
    for j in range(8):
        if AA[i][j] != 0:
            AA[i][j] = alog[(255 + log[AA[i][j] & 0xFF] - log[pivot & 0xFF]) % 255]
    for t in range(4):
        if i != t:
            for j in range(i+1, 8):
                AA[t][j] ^= mul(AA[i][j], AA[t][i])
            AA[t][i] = 0

iG = [[0] * 4 for i in range(4)]

for i in range(4):
    for j in range(4):
        iG[i][j] = AA[i][j + 4]

def mul4(a, bs):
    if a == 0:
        return 0
    r = 0
    for b in bs:
        r <<= 8
        if b != 0:
            r = r | mul(a, b)
    return r

T1 = []
T2 = []
T3 = []
T4 = []
T5 = []
T6 = []
T7 = []
T8 = []
U1 = []
U2 = []
U3 = []
U4 = []

for t in range(256):
    s = S[t]
    T1.append(mul4(s, G[0]))
    T2.append(mul4(s, G[1]))
    T3.append(mul4(s, G[2]))
    T4.append(mul4(s, G[3]))

    s = Si[t]
    T5.append(mul4(s, iG[0]))
    T6.append(mul4(s, iG[1]))
    T7.append(mul4(s, iG[2]))
    T8.append(mul4(s, iG[3]))

    U1.append(mul4(t, iG[0]))
    U2.append(mul4(t, iG[1]))
    U3.append(mul4(t, iG[2]))
    U4.append(mul4(t, iG[3]))

# round constants
rcon = [1]
r = 1
for t in range(1, 30):
    r = mul(2, r)
    rcon.append(r)

del A
del AA
del pivot
del B
del G
del box
del log
del alog
del i
del j
del r
del s
del t
del mul
del mul4
del cox
del iG

class rijndael:
    def __init__(self, key, block_size = 16):
        if block_size != 16 and block_size != 24 and block_size != 32:
            raise ValueError('Invalid block size: ' + str(block_size))
        if len(key) != 16 and len(key) != 24 and len(key) != 32:
            raise ValueError('Invalid key size: ' + str(len(key)))
        self.block_size = block_size

        ROUNDS = num_rounds[len(key)][block_size]
        BC = block_size // 4
        # encryption round keys
        Ke = [[0] * BC for i in range(ROUNDS + 1)]
        # decryption round keys
        Kd = [[0] * BC for i in range(ROUNDS + 1)]
        ROUND_KEY_COUNT = (ROUNDS + 1) * BC
        KC = len(key) // 4

        # copy user material bytes into temporary ints
        tk = []
        for i in range(0, KC):
            tk.append((key[i * 4] << 24) | (key[i * 4 + 1] << 16) |
                (key[i * 4 + 2]) << 8 | key[i * 4 + 3])

        # copy values into round key arrays
        t = 0
        j = 0
        while j < KC and t < ROUND_KEY_COUNT:
            Ke[t // BC][t % BC] = tk[j]
            Kd[ROUNDS - (t // BC)][t % BC] = tk[j]
            j += 1
            t += 1
        tt = 0
        rconpointer = 0
        while t < ROUND_KEY_COUNT:
            # extrapolate using phi (the round key evolution function)
            tt = tk[KC - 1]
            tk[0] ^= (S[(tt >> 16) & 0xFF] & 0xFF) << 24 ^  \
                     (S[(tt >>  8) & 0xFF] & 0xFF) << 16 ^  \
                     (S[ tt        & 0xFF] & 0xFF) <<  8 ^  \
                     (S[(tt >> 24) & 0xFF] & 0xFF)       ^  \
                     (rcon[rconpointer]    & 0xFF) << 24
            rconpointer += 1
            if KC != 8:
                for i in range(1, KC):
                    tk[i] ^= tk[i-1]
            else:
                for i in range(1, KC // 2):
                    tk[i] ^= tk[i-1]
                tt = tk[KC // 2 - 1]
                tk[KC // 2] ^= (S[ tt        & 0xFF] & 0xFF)       ^ \
                              (S[(tt >>  8) & 0xFF] & 0xFF) <<  8 ^ \
                              (S[(tt >> 16) & 0xFF] & 0xFF) << 16 ^ \
                              (S[(tt >> 24) & 0xFF] & 0xFF) << 24
                for i in range(KC // 2 + 1, KC):
                    tk[i] ^= tk[i-1]
            # copy values into round key arrays
            j = 0
            while j < KC and t < ROUND_KEY_COUNT:
                Ke[t // BC][t % BC] = tk[j]
                Kd[ROUNDS - (t // BC)][t % BC] = tk[j]
                j += 1
                t += 1
        # inverse MixColumn where needed
        for r in range(1, ROUNDS):
            for j in range(BC):
                tt = Kd[r][j]
                Kd[r][j] = U1[(tt >> 24) & 0xFF] ^ \
                           U2[(tt >> 16) & 0xFF] ^ \
                           U3[(tt >>  8) & 0xFF] ^ \
                           U4[ tt        & 0xFF]
        self.Ke = Ke
        self.Kd = Kd

    def encrypt(self, plaintext):
        if len(plaintext) != self.block_size:
            raise ValueError('wrong block length, expected ' + 
                str(self.block_size) + ' got ' + str(len(plaintext)))
        Ke = self.Ke

        BC = self.block_size // 4
        ROUNDS = len(Ke) - 1
        if BC == 4:
            SC = 0
        elif BC == 6:
            SC = 1
        else:
            SC = 2
        s1 = shifts[SC][1][0]
        s2 = shifts[SC][2][0]
        s3 = shifts[SC][3][0]
        a = [0] * BC
        # temporary work array
        t = []
        # plaintext to ints + key
        for i in range(BC):
            t.append((plaintext[i * 4    ] << 24 |
                      plaintext[i * 4 + 1] << 16 |
                      plaintext[i * 4 + 2] <<  8 |
                      plaintext[i * 4 + 3]        ) ^ Ke[0][i])
        # apply round transforms
        for r in range(1, ROUNDS):
            for i in range(BC):
                a[i] = (T1[(t[ i           ] >> 24) & 0xFF] ^
                        T2[(t[(i + s1) % BC] >> 16) & 0xFF] ^
                        T3[(t[(i + s2) % BC] >>  8) & 0xFF] ^
                        T4[ t[(i + s3) % BC]        & 0xFF]  ) ^ Ke[r][i]
            t = copy.copy(a)
        # last round is special
        result = []
        for i in range(BC):
            tt = Ke[ROUNDS][i]
            result.append((S[(t[ i           ] >> 24) & 0xFF] ^ (tt >> 24)) & 0xFF)
            result.append((S[(t[(i + s1) % BC] >> 16) & 0xFF] ^ (tt >> 16)) & 0xFF)
            result.append((S[(t[(i + s2) % BC] >>  8) & 0xFF] ^ (tt >>  8)) & 0xFF)
            result.append((S[ t[(i + s3) % BC]        & 0xFF] ^  tt       ) & 0xFF)
        return bytearray(result)

    def decrypt(self, ciphertext):
        if len(ciphertext) != self.block_size:
            raise ValueError('wrong block length, expected ' + 
                str(self.block_size) + ' got ' + str(len(ciphertext)))
        Kd = self.Kd

        BC = self.block_size // 4
        ROUNDS = len(Kd) - 1
        if BC == 4:
            SC = 0
        elif BC == 6:
            SC = 1
        else:
            SC = 2
        s1 = shifts[SC][1][1]
        s2 = shifts[SC][2][1]
        s3 = shifts[SC][3][1]
        a = [0] * BC
        # temporary work array
        t = [0] * BC
        # ciphertext to ints + key
        for i in range(BC):
            t[i] = (ciphertext[i * 4    ] << 24 |
                    ciphertext[i * 4 + 1] << 16 |
                    ciphertext[i * 4 + 2] <<  8 |
                    ciphertext[i * 4 + 3]        ) ^ Kd[0][i]
        # apply round transforms
        for r in range(1, ROUNDS):
            for i in range(BC):
                a[i] = (T5[(t[ i           ] >> 24) & 0xFF] ^
                        T6[(t[(i + s1) % BC] >> 16) & 0xFF] ^
                        T7[(t[(i + s2) % BC] >>  8) & 0xFF] ^
                        T8[ t[(i + s3) % BC]        & 0xFF]  ) ^ Kd[r][i]
            t = copy.copy(a)
        # last round is special
        result = []
        for i in range(BC):
            tt = Kd[ROUNDS][i]
            result.append((Si[(t[ i           ] >> 24) & 0xFF] ^ (tt >> 24)) & 0xFF)
            result.append((Si[(t[(i + s1) % BC] >> 16) & 0xFF] ^ (tt >> 16)) & 0xFF)
            result.append((Si[(t[(i + s2) % BC] >>  8) & 0xFF] ^ (tt >>  8)) & 0xFF)
            result.append((Si[ t[(i + s3) % BC]        & 0xFF] ^  tt       ) & 0xFF)
        return bytearray(result)

def encrypt(key, block):
    return rijndael(key, len(block)).encrypt(block)

def decrypt(key, block):
    return rijndael(key, len(block)).decrypt(block)

def test():
    def t(kl, bl):
        b = 'b' * bl
        r = rijndael('a' * kl, bl)
        assert r.decrypt(r.encrypt(b)) == b
    t(16, 16)
    t(16, 24)
    t(16, 32)
    t(24, 16)
    t(24, 24)
    t(24, 32)
    t(32, 16)
    t(32, 24)
    t(32, 32)


################ COMPAT ###
import sys, binascii
if sys.version_info >= (3,0):
    def raw_input(s):
        return input(s)
    
    def a2b_hex(s):
        b = binascii.a2b_hex(bytearray(s, "ascii"))  
        return b  
    def b2a_hex(b):
        return binascii.b2a_hex(b).decode("ascii")        
    def b2a_base64(b):
        return binascii.b2a_base64(b).decode("ascii")    
else:
    def a2b_hex(s):
        return binascii.a2b_hex(s)
    def b2a_hex(b):
        return binascii.b2a_hex(b)
    def b2a_base64(b):
        return binascii.b2a_base64(b)

################ CRYPTOMATH ###

import math, hashlib, hmac

def bytesToNumber(bytes):
    total = 0
    multiplier = 1
    for count in range(len(bytes)-1, -1, -1):
        byte = bytes[count]
        total += multiplier * byte
        multiplier *= 256
    return total

def numberToBytes(n, howManyBytes=None):
    if not howManyBytes:
        howManyBytes = numBytes(n)
    bytes = bytearray(howManyBytes)
    for count in range(howManyBytes-1, -1, -1):
        bytes[count] = int(n % 256)
        n >>= 8
    return bytes
    
def stringToNumber(s):
    return bytesToNumber(bytearray(s))
    
def numBits(n):
    if n==0:
        return 0
    s = "%x" % n
    return ((len(s)-1)*4) + \
    {'0':0, '1':1, '2':2, '3':2,
     '4':3, '5':3, '6':3, '7':3,
     '8':4, '9':4, 'a':4, 'b':4,
     'c':4, 'd':4, 'e':4, 'f':4,
     }[s[0]]
    
def numBytes(n):
    if n==0:
        return 0
    bits = numBits(n)
    return int(math.ceil(bits / 8.0))

def SHA256(b):
    return bytearray(hashlib.sha256(b).digest())

def HMAC_SHA256(k, b):
    return bytearray(hmac.new(bytes(k), bytes(b), hashlib.sha256).digest())

def constTimeCompare(a, b):
    if len(a) != len(b):
        return False
    result = 0
    for x in range(len(a)):
        result |= a[x]^b[x]
    if result:
        return False
    return True

################ ECDSA_WRAPPERS ###

def ec256Generate(extraRandBytes=None):
    # ECDSA key generation per FIPS 186-3 B.4.1
    # (except we use 32 extra random bytes instead of 8 before reduction)
    # Random bytes taken from /dev/urandom as well as any extraRandBytes
    # REVIEW THIS CAREFULLY!  CHANGE AT YOUR PERIL!
    randBytes0 = bytearray(os.urandom(64))
    if extraRandBytes:
        randBytes0 += bytearray(extraRandBytes)
    randBytes = HMAC_SHA256(randBytes0, bytearray([1]))
    randBytes+= HMAC_SHA256(randBytes0, bytearray([2]))
    c = bytesToNumber(randBytes) 
    n = generator_256.order()
    d = (c % (n-1))+1        
    privateKey = numberToBytes(d, 32)
    publicKeyPoint = generator_256 * d        
    publicKey = numberToBytes(publicKeyPoint.x(), 32) + \
                numberToBytes(publicKeyPoint.y(), 32)
    return (privateKey, publicKey)

def ecdsa256Sign(privateKey, publicKey, dataToSign):
    privateKeyNum = bytesToNumber(privateKey)
    hash = SHA256(dataToSign)
    g = generator_256
    n = g.order()
    x = bytesToNumber(publicKey[:32])
    y = bytesToNumber(publicKey[32:])        
    pubkey = Public_key(g, Point(g.curve(), x,y))    
    privkey = Private_key(pubkey, privateKeyNum)    

    # Generating random nonce k per FIPS 186-3 B.5.1:
    # (except we use 32 extra bytes instead of 8 before reduction)
    # Random bytes taken from /dev/urandom as well as HMAC(privkey,hash)
    # REVIEW THIS CAREFULLY!!!  CHANGE AT YOUR PERIL!!!
    randBytes0 = bytearray(os.urandom(64))
    randBytes0+= HMAC_SHA256(privateKey, hash)
    randBytes = HMAC_SHA256(randBytes0, bytearray([1]))
    randBytes+= HMAC_SHA256(randBytes0, bytearray([2]))                       
    c = bytesToNumber(randBytes) 
    k = (c % (n-1))+1                
    hashNum = bytesToNumber(hash)
    sig = privkey.sign(hashNum, k)
    assert(pubkey.verifies(hashNum, sig))
    return numberToBytes(sig.r, 32) + numberToBytes(sig.s, 32)

def ecdsa256Verify(publicKey, dataToVerify, signature):
    hashNum = bytesToNumber(SHA256(dataToVerify))
    g = generator_256  
    x = bytesToNumber(publicKey[:32])
    y = bytesToNumber(publicKey[32:])        
    pubkey = Public_key(g, Point(g.curve(), x,y))
    sig = Signature(bytesToNumber(signature[:32]), 
                            bytesToNumber(signature[32:]))
    return pubkey.verifies(hashNum, sig)

################ TIME ###

import time, calendar, datetime

def posixTimeToStr(u, includeSeconds=False):    
    t = time.gmtime(u)
    if includeSeconds:
        s = time.strftime("%Y-%m-%dT%H:%M:%SZ", t)        
    else:
        s = time.strftime("%Y-%m-%dT%H:%MZ", t)
    return s
    
def getDefaultExpirationStr():
    days = pinDays = 550 # About 1.5 years
    currentTime = int(time.time()) # Get time in seconds
    exp = currentTime + (24*60*60) * days
    return posixTimeToStr(exp)

def parseTimeArg(arg):
    # Allow them to specify as much or as little of
    # ISO8601 as they want
    if arg.endswith("Z"):
        arg = arg[:-1]
    patterns = ["%Y-%m-%dT%H:%M", "%Y-%m-%dT%H", 
        "%Y-%m-%d", "%Y-%m", "%Y"]
    t = None
    for p in patterns:
        try:
            t = time.strptime(arg, p)
            break
        except ValueError:
            pass
    if not t:
        s = posixTimeToStr(time.time())
        printError(
'''Invalid time format, use e.g. "%s" (current time)
or some prefix, such as: "%s", "%s", or "%s"''' % 
            (s, s[:13], s[:10], s[:4]))    
    u = int(calendar.timegm(t)//60)
    if u < 0:
        printError("Time too early, epoch starts at 1970.")
    return u

def getDateStr():
    now = datetime.datetime.now()
    return now.strftime("%Y-%m-%d") 

################ CODEC ###

class Writer:
    def __init__(self, totalLength):
        self.index = 0
        self.bytes = bytearray(totalLength)

    def add(self, x, elementLength):
        """Writes 'elementLength' bytes, input is either an integer
         (written as big-endian) or a sequence of bytes"""
        if isinstance(x, int):
            assert(x >= 0 and x < 2**(8*elementLength))
            newIndex = self.index + elementLength-1
            while newIndex >= self.index:
                self.bytes[newIndex] = x & 0xFF
                x >>= 8
                newIndex -= 1
        else:
            assert(len(x) == elementLength)
            for i in range(elementLength):
                self.bytes[self.index + i] = x[i]                
        self.index += elementLength

    def addVarSeq(self, seq, elementLength, lengthLength):
        """Writes a sequence of elements prefixed by a 
        total-length field of lengthLength bytes"""
        self.add(len(seq)*elementLength, lengthLength)
        for e in seq:
            self.add(e, elementLength)

class Parser:
    def __init__(self, bytes):
        self.bytes = bytes
        self.index = 0

    def getInt(self, elementLength):
        """Reads an integer of 'length' bytes"""
        if self.index + elementLength > len(self.bytes):
            raise SyntaxError()
        x = 0
        for count in range(elementLength):
            x <<= 8
            x |= self.bytes[self.index]
            self.index += 1
        return x

    def getBytes(self, elementLength):
        """Reads some number of bytes as determined by 'lengthBytes'"""
        bytes = self.bytes[self.index : self.index + elementLength]
        self.index += elementLength
        return bytes

    def getVarSeqBytes(self, elementLength, lengthLength):
        dataLength = self.getInt(lengthLength)
        if dataLength % elementLength != 0:
            raise SyntaxError()
        return [self.getBytes(elementLength) for x in \
                range(dataLength//elementLength)]


################ ASN1 PARSER ###
# Returns bytearray encoding an ASN1 length field
# Assumes maximum of 2-byte length
def asn1Length(x):
    if x < 128:
        return bytearray([x])
    if x < 256:
        return bytearray([0x81,x])  
    if x < 65536:
        return bytearray([0x82, int(x//256), x % 256])  
    assert(False)
    
#Takes a byte array which has a DER TLV field at its head
class ASN1Parser:
    def __init__(self, bytes, offset = 0):
        p = Parser(bytes)
        self.type = p.getInt(1) #skip Type

        #Get Length
        self.length = self._getASN1Length(p)
        
        # Header length is however many bytes read so far
        self.headerLength = p.index        

        #Get Value
        self.value = p.getBytes(self.length)
        
        # This value tracks the offset of this TLV field
        # in some enclosing structure (ie an X.509 cert) 
        self.offset = offset
        

    #Assuming this is a sequence...
    def getChild(self, which):
        p = Parser(self.value)
        for x in range(which+1):
            if p.index == len(p.bytes):
                return None
            markIndex = p.index
            p.getInt(1) #skip Type
            length = self._getASN1Length(p)
            p.getBytes(length)
        return ASN1Parser(p.bytes[markIndex : p.index], \
                            self.offset + self.headerLength + markIndex)

    #Assuming this is a tagged element...
    def getTagged(self):
        return ASN1Parser(self.value, self.offset + self.headerLength)

    def getTotalLength(self):
        return self.headerLength + self.length
        
    def getTotalBytes(self):
        return bytearray([self.type]) + asn1Length(self.length) + self.value

    #Decode the ASN.1 DER length field
    def _getASN1Length(self, p):
        firstLength = p.getInt(1)
        if firstLength<=127:
            lengthLength = 1
            return firstLength
        else:
            lengthLength = firstLength & 0x7F
            return p.getInt(lengthLength)
        

################ CONSTANTS ###

class TACK_Pin_Type:
    v1 = 1
    strings = (None, "v1")

class TACK_Sig_Type:
    v1_key = 1
    v1_cert = 2
    all = (v1_key, v1_cert)
    strings = (None, "v1_key", "v1_cert")
        

################ STRUCTURES ###

def writeBytes(b):
    s = b2a_hex(b)
    retVal = ""
    while s:
        retVal += s[:32]
        s = s[32:]
        if len(s):
            retVal += "\n                           "
    return retVal
        
class TACK_Pin:
    length = 73
    
    def __init__(self):
        self.pin_type = 0
        self.pin_label = bytearray(8)
        self.pin_key = bytearray(64)
    
    def generate(self, pin_type, pin_label, pin_key):
        self.pin_type = pin_type
        self.pin_label = pin_label
        self.pin_key = pin_key
            
    def parse(self, b):
        p = Parser(b)
        self.pin_type = p.getInt(1)
        if self.pin_type != TACK_Pin_Type.v1:
            raise SyntaxError()
        self.pin_label = p.getBytes(8)
        self.pin_key = p.getBytes(64)
        assert(p.index == len(b)) # did we fully consume byte-array?
        
    def write(self):        
        if self.pin_type != TACK_Pin_Type.v1:
            raise SyntaxError()        
        w = Writer(TACK_Pin.length)
        w.add(self.pin_type, 1)
        w.add(self.pin_label, 8)  
        w.add(self.pin_key, 64)
        assert(w.index == len(w.bytes)) # did we fill entire byte-array?            
        return w.bytes  

    def writeText(self):
        if self.pin_type != TACK_Pin_Type.v1:
            raise SyntaxError()
        s = \
"""pin_type               = %s
pin_label              = 0x%s
pin_key                = 0x%s\n""" % \
(TACK_Pin_Type.strings[self.pin_type], 
writeBytes(self.pin_label),
writeBytes(self.pin_key))
        return s
        
           
class TACK_Sig:
    length = 105
        
    def __init__(self):
        self.sig_type = 0
        self.sig_expiration = 0
        self.sig_revocation = 0                
        self.sig_target_sha256 = bytearray(32)
        self.signature = bytearray(64)
        
    def generate(self, sig_type, sig_expiration, sig_revocation,
                sig_target_sha256, pin, signFunc):
        self.sig_type = sig_type
        self.sig_expiration = sig_expiration
        self.sig_revocation = sig_revocation                
        self.sig_target_sha256 = sig_target_sha256
        self.signature = signFunc(pin.write() + self.write()[:-64])
    
    def parse(self, b):
        p = Parser(b)
        self.sig_type = p.getInt(1)
        if self.sig_type not in TACK_Sig_Type.all:
            raise SyntaxError()
        self.sig_expiration = p.getInt(4)
        self.sig_revocation = p.getInt(4)            
        self.sig_target_sha256 = p.getBytes(32)
        self.signature = p.getBytes(64)
        assert(p.index == len(b)) # did we fully consume byte-array?
        
    def write(self):
        if self.sig_type not in TACK_Sig_Type.all:
            raise SyntaxError()
        w = Writer(TACK_Sig.length)
        w.add(self.sig_type, 1)
        w.add(self.sig_expiration, 4)
        w.add(self.sig_revocation, 4)
        w.add(self.sig_target_sha256, 32)
        w.add(self.signature, 64)
        assert(w.index == len(w.bytes)) # did we fill entire byte-array?
        return w.bytes

    def writeText(self):
        if self.sig_type not in TACK_Sig_Type.all:
            raise SyntaxError()
        s = \
"""sig_type               = %s
sig_expiration         = %s
sig_revocation         = %s
sig_target_sha256      = 0x%s
signature              = 0x%s\n""" % \
(TACK_Sig_Type.strings[self.sig_type], 
posixTimeToStr(self.sig_expiration*60),
posixTimeToStr(self.sig_revocation*60),
writeBytes(self.sig_target_sha256),
writeBytes(self.signature))
        return s
   
        
class TACK_Break_Sig:
    length = 72
    
    def __init__(self):
        self.pin_label = bytearray(8)
        self.signature = bytearray(64)
        
    def generate(self, pin_label, signature):
        self.pin_label = pin_label
        self.signature = signature
        
    def parse(self, b):
        p = Parser(b)
        self.pin_label = p.getBytes(8)
        self.signature = p.getBytes(64)
        assert(p.index == len(b)) # did we fully consume byte-array?
        
    def write(self):
        w = Writer(TACK_Break_Sig.length)
        w.add(self.pin_label, 8)
        w.add(self.signature, 64)
        assert(w.index == len(w.bytes)) # did we fill entire byte-array?        
        return w.bytes

    def writeText(self, i):
        s = \
"""break_label[%02d]        = 0x%s
break_signature[%02d]    = 0x%s\n""" % \
(i, writeBytes(self.pin_label), 
 i, writeBytes(self.signature))
        return s


class TACK_Break_Sigs:
    maxLen = 20
    
    def __init__(self):
        self.break_sigs = []
    
    def isFull(self):
        return len(self.break_sigs) == TACK_Break_Sigs.maxLen
    
    def add(self, break_sig):
        assert(len(self.break_sigs) < TACK_Break_Sigs.maxLen)
        assert(isinstance(break_sig, TACK_Break_Sig))
        self.break_sigs.append(break_sig)
    
    def parse(self, b):
        p = Parser(b)
        numBreakSigs = int(p.getInt(2) // TACK_Break_Sig.length)
        if numBreakSigs > TACK_Break_Sigs.maxLen:
            raise SyntaxError("Too many break_sigs")
        self.break_sigs = []
        for x in range(numBreakSigs):
            break_sig = TACK_Break_Sig()
            break_sig.parse(p.getBytes(TACK_Break_Sig.length))
            self.break_sigs.append(break_sig)
    
    def write(self):
        w = Writer(2 + TACK_Break_Sig.length * len(self.break_sigs))
        w.add(len(self.break_sigs) * TACK_Break_Sig.length, 2)
        for x in range(len(self.break_sigs)):
            w.add(self.break_sigs[x].write(), TACK_Break_Sig.length)
        assert(w.index == len(w.bytes)) # did we fill entire byte-array?                    
        return w.bytes

    def writeText(self):
        return "".join(b.writeText(i) for i,b in enumerate(self.break_sigs))


class TACK:
    def __init__(self):
        self.pin = None
        self.sig = None
        
    def parse(self, b):
        assert(len(b) == TACK_Pin.length + TACK_Sig.length)
        self.pin = TACK_Pin()
        self.sig = TACK_Sig()
        self.pin.parse(b[ : TACK_Pin.length])
        b = b[TACK_Pin.length : ]
        self.sig.parse(b[ : TACK_Sig.length])
        
    def write(self):
        w = Writer(TACK_Pin.length + TACK_Sig.length)
        w.add(self.pin.write(), TACK_Pin.length) 
        w.add(self.sig.write(), TACK_Sig.length)
        return w.bytes

    def writeText(self):
        return "%s%s" % \
            (self.pin.writeText(), self.sig.writeText())

################ SSL CERT ###

def dePemCert(b):
    start = b.find(b"-----BEGIN CERTIFICATE-----")
    end = b.find(b"-----END CERTIFICATE-----")
    if start == -1:
        raise SyntaxError("Missing PEM prefix")
    if end == -1:
        raise SyntaxError("Missing PEM postfix")
    b = b[start+len(b"-----BEGIN CERTIFICATE-----") : end]
    return bytearray(binascii.a2b_base64(b))

def pemCert(b):
    s1 = b2a_base64(b)[:-1] # remove terminating \n
    s2 = ""
    while s1:
        s2 += s1[:64] + "\n"
        s1 = s1[64:]
    s = "-----BEGIN CERTIFICATE-----\n" + s2 + \
            "-----END CERTIFICATE-----"     
    return bytearray(s, "ascii")
        
class SSL_Cert:
    def __init__(self):
        self.key_sha256 = bytearray(32)
        self.cert_sha256 = bytearray(32)
    
    def parse(self, b):
        try:
            b = dePemCert(b)
        except SyntaxError:
            pass
        p = ASN1Parser(b)

        #Get the tbsCertificate
        tbsCertificateP = p.getChild(0)

        #Is the optional version field present?
        #This determines which index the key is at
        if tbsCertificateP.value[0]==0xA0:
            subjectPublicKeyInfoIndex = 6
        else:
            subjectPublicKeyInfoIndex = 5             
        #Get the subjectPublicKeyInfo
        spkiP = tbsCertificateP.getChild(\
                                    subjectPublicKeyInfoIndex)
        self.cert_sha256 = SHA256(b)
        self.key_sha256 = SHA256(spkiP.getTotalBytes())
    
    def writeText(self):
        s = \
"""key_sha256             = 0x%s
cert_sha256            = 0x%s\n""" % (\
        writeBytes(self.key_sha256),
        writeBytes(self.cert_sha256))
        return s
        

################ TACK CERT ###

class TACK_Cert:
    oid_TACK = bytearray(b"\x2B\x06\x01\x04\x01\x82\xB0\x34\x01")
    oid_TACK_Break_Sigs = bytearray(b"\x2B\x06\x01\x04\x01\x82\xB0\x34\x02")
    
    def __init__(self):
        self.TACK = None
        self.break_sigs = None
        self.preExtBytes = None 
        self.extBytes = None
        self.postExtBytes = None
    
    def generate(self, pin=None, sig=None, break_sigs=None):
        self.TACK = None
        self.break_sigs = None
        self.preExtBytes = a2b_hex(
"a003020102020100300d06092a864886f70d0101050500300f310d300b06035504031"
"3045441434b301e170d3031303730353138303534385a170d33343037303431383035"
"34385a300f310d300b060355040313045441434b301f300d06092a864886f70d01010"
"10500030e00300b0204010203040203010001")
        # Below is BasicConstraints, saving space by omitting
        #self.extBytes = binascii.a2b_hex(\
#"300c0603551d13040530030101ff")
        self.extBytes = bytearray()
        self.postExtBytes = a2b_hex(
"300d06092a864886f70d01010505000303003993")
    
    def parse(self, b):
        try:
            b = dePemCert(b)
        except SyntaxError:
            pass        
        p = ASN1Parser(b)
        self.extBytes = bytearray()

        #Get the tbsCertificate
        tbsCertificateP = p.getChild(0)
        versionP = tbsCertificateP.getChild(0)        
        if versionP.type != 0xA0: # i.e. tag of [0], version
            raise SyntaxError("X.509 version field not present")
        versionPP = versionP.getTagged()
        if versionPP.value != bytearray([0x02]):
            raise SyntaxError("X.509 version field does not equal v3")

        # Find extensions element
        x = 0
        while 1:
            certFieldP = tbsCertificateP.getChild(x)
            if not certFieldP:
                raise SyntaxError("X.509 extensions not present")
            if certFieldP.type == 0xA3: # i.e. tag of [3], extensions
                break
            x += 1

        self.preExtBytes = b[versionP.offset : certFieldP.offset]
        self.extBytes = bytearray()

        # Iterate through extensions
        x = 0
        certFieldPP = certFieldP.getTagged()
        while 1:
            extFieldP = certFieldPP.getChild(x)
            if not extFieldP:
                break
                    
            # Check the extnID and parse out TACK if present
            extnIDP = extFieldP.getChild(0)            
            if extnIDP.value == TACK_Cert.oid_TACK:
                if self.TACK:
                    raise SyntaxError("More than one TACK")                
                self.TACK = TACK()
                self.TACK.parse(extFieldP.getChild(1).value)                    
            elif extnIDP.value == TACK_Cert.oid_TACK_Break_Sigs:
                if self.break_sigs:
                    raise SyntaxError("More than one TACK_Break_Sigs")                
                self.break_sigs = TACK_Break_Sigs()
                self.break_sigs.parse(extFieldP.getChild(1).value)                    
            else:  
                # Collect all non-TACK extensions:
                self.extBytes += b[extFieldP.offset : \
                                extFieldP.offset + extFieldP.getTotalLength()]
            x += 1                

        # Finish copying the tail of the certificate
        self.postExtBytes = b[certFieldP.offset + certFieldP.getTotalLength():]
        
    def write(self):        
        b = bytearray(0)
        if self.TACK:
            # type=SEQ,len=?,type=6,len=9(for OID),
            # type=4,len=?,TACK
            TACKBytes = self.TACK.write()            
            b = bytearray([4]) + asn1Length(len(TACKBytes)) + TACKBytes
            b = bytearray([6,9]) + self.oid_TACK + b
            b = bytearray([0x30]) + asn1Length(len(b)) + b
        if self.break_sigs:
            breakBytes = self.break_sigs.write()
            b2 = bytearray([4]) + asn1Length(len(breakBytes)) + breakBytes
            b2 = bytearray([6,9]) + self.oid_TACK_Break_Sigs + b2
            b2 = bytearray([0x30]) + asn1Length(len(b2)) + b2
            b += b2
        
        b = b + self.extBytes # add non-TACK extensions after TACK
        # Add length fields for extensions and its enclosing tag
        b = bytearray([0x30]) + asn1Length(len(b)) + b
        b = bytearray([0xA3]) + asn1Length(len(b)) + b
        # Add prefix of tbsCertificate, then its type/length fields
        b = self.preExtBytes + b
        b = bytearray([0x30]) + asn1Length(len(b)) + b
        # Add postfix of Certificate (ie SignatureAlgorithm, SignatureValue)
        # then its prefix'd type/length fields
        b = b + self.postExtBytes
        b = bytearray([0x30]) + asn1Length(len(b)) + b
        return b

    def writeText(self):
        s = ""
        if self.TACK:
            s += self.TACK.writeText()
        if self.break_sigs:
            s += self.break_sigs.writeText()
        if not s:
            return "No TACK structures\n"
        else:
            return s


################ KEY FILE ###

import os
#  File format:
#
#  magic number   3 bytes = 0x9a6127
#  version        1  byte
#  iter_count     4 bytes
#  salt          16 bytes
#  IV            16 bytes         } auth
#    EC privkey  32 bytes  } enc  } auth
#  EC pubkey     64 bytes         } auth
#  HMAC          32 bytes	
# 
#  total		168

def xorbytes(s1, s2):
    return bytearray([a^b for a,b in zip(s1,s2)])

# Uses PBKDF2-HMAC-SHA256 to produce a 32-byte key
def pbkdf2_hmac_sha256(password, salt, iterations):
    m = salt + bytearray([0,0,0,1])
    result = bytearray(32)
    for c in range(iterations):
        m = HMAC_SHA256(bytearray(password, "ascii"), m)
        result = xorbytes(m, result)
    return result

# Uses PBKDF2, then HMAC-SHA256 as PRF to derive independent 32-byte keys
def deriveKeyFileKeys(password, salt, iter_count):
    assert(iter_count>0)
    masterKey = pbkdf2_hmac_sha256(password, salt, iter_count)
    encKey = HMAC_SHA256(masterKey, bytearray([1]))
    authKey = HMAC_SHA256(masterKey, bytearray([2]))
    return (encKey, authKey)

def aes_cbc_decrypt(key, IV, ciphertext):
    cipher = rijndael(key, 16)
    assert(len(ciphertext) % 16 == 0) # no padding
    chainBlock = IV
    plaintext = bytearray() # not efficient, but doesn't matter here
    for c in range(len(ciphertext)//16):
        cipherBlock = ciphertext[c*16 : (c*16)+16]
        plaintext += xorbytes(cipher.decrypt(cipherBlock), chainBlock)
        chainBlock = cipherBlock
    return plaintext

def aes_cbc_encrypt(key, IV, plaintext):
    cipher = rijndael(key, 16)
    assert(len(plaintext) % 16 == 0) # no padding
    chainBlock = IV
    ciphertext = bytearray() # not efficient, but doesn't matter here
    for c in range(len(plaintext)//16):
        plainBlock = plaintext[c*16 : (c*16)+16]
        chainBlock = cipher.encrypt(xorbytes(plainBlock, chainBlock))
        ciphertext += chainBlock
    return ciphertext     

class TACK_KeyFileViewer:
    def __init__(self):
        self.version = 0
        self.iter_count = 0
        self.salt = bytearray(16)
        self.IV = bytearray(16)
        self.ciphertext = bytearray(64)
        self.public_key = bytearray(64)
        self.mac = bytearray(32)
        
    def parse(self, b):
        p = Parser(b)
        magic = p.getBytes(3)
        if magic != TACK_KeyFile.magic:
            raise SyntaxError("Bad magic number in Secret File")
        self.version = p.getInt(1)
        if self.version != 1:
            raise SyntaxError("Bad version in Secret File")
        self.iter_count = p.getInt(4)
        self.salt = p.getBytes(16)
        self.IV = p.getBytes(16)
        self.ciphertext = p.getBytes(32)
        self.public_key = p.getBytes(64)
        self.mac = bytearray(p.getBytes(32))
        assert(p.index == len(b)) # did we fully consume byte-array?

    def writeText(self):
        s = \
"""version                = %d
iter_count             = %d
salt                   = 0x%s
IV                     = 0x%s
ciphertext             = 0x%s
public_key             = 0x%s
mac                    = 0x%s\n""" % \
        (self.version, 
        self.iter_count,
        writeBytes(self.salt),
        writeBytes(self.IV),
        writeBytes(self.ciphertext),
        writeBytes(self.public_key),
        writeBytes(self.mac))
        return s        
        
    
class TACK_KeyFile:
    magic = bytearray([0x9A,0x61,0x27])

    def __init__(self):
        self.version = 0
        self.private_key = bytearray(32)
        self.public_key = bytearray(64)
        self.iter_count = 0
        
    def generate(self, extraRandBytes=None):
        self.version = 1
        self.private_key, self.public_key = ec256Generate(extraRandBytes)
        self.iter_count = 8192

    def sign(self, bytesToSign):
        signature = ecdsa256Sign(self.private_key, self.public_key, bytesToSign)
        # Double-check value before returning
        assert(ecdsa256Verify(self.public_key, bytesToSign, signature))
        return signature

    def parse(self, b, password):
        p = Parser(b)
        magic = p.getBytes(3)
        if magic != TACK_KeyFile.magic:
            raise SyntaxError("Bad magic number in Secret File")
        self.version = p.getInt(1)
        if self.version != 1:
            raise SyntaxError("Bad version in Secret File")
        self.iter_count = p.getInt(4)
        salt = p.getBytes(16)
        IV = p.getBytes(16)
        ciphertext = p.getBytes(32)
        self.public_key = p.getBytes(64)
        mac = bytearray(p.getBytes(32))
        assert(p.index == len(b)) # did we fully consume byte-array?

        encKey, authKey = deriveKeyFileKeys(password, salt, self.iter_count)
        macData = IV + ciphertext + self.public_key
        calcMac = HMAC_SHA256(authKey, macData)
        if not constTimeCompare(calcMac, mac):
            return False        
        plaintext = aes_cbc_decrypt(encKey, IV, ciphertext)
        self.private_key = plaintext
        return True
    
    def write(self, password):
        salt = bytearray(os.urandom(16))
        IV = bytearray(os.urandom(16))
        encKey, authKey = deriveKeyFileKeys(password, salt, self.iter_count)
        plaintext = self.private_key
        ciphertext = aes_cbc_encrypt(encKey, IV, plaintext)
        macData = IV + ciphertext + self.public_key
        mac = HMAC_SHA256(authKey, macData)        
        w = Writer(168)
        w.add(TACK_KeyFile.magic, 3)
        w.add(self.version, 1)
        w.add(self.iter_count, 4)
        w.add(salt, 16)
        w.add(IV, 16)
        w.add(ciphertext, 32)
        w.add(self.public_key, 64)
        w.add(mac, 32)
        assert(w.index == len(w.bytes)) # did we fill entire byte-array?
        return w.bytes


################ TESTS ###


def testStructures():
    pin = TACK_Pin()
    sig = TACK_Sig()
    
    pin.generate(TACK_Pin_Type.v1, os.urandom(8), os.urandom(64))

    # Test reading/writing OOC pin
    pin2 = TACK_Pin()
    pin2.parse(pin.write())
    assert(pin.write() == pin2.write())


    # Test reading/writing TACK_Sig
    privKey, pubKey = ec256Generate()
    sig.generate(TACK_Sig_Type.v1_cert,
                 100000, 200000, os.urandom(32), pin,
                 lambda b:ecdsa256Sign(privKey, pubKey, b))
    sig2 = TACK_Sig()
    sig2.parse(sig.write())
    assert(sig.write() == sig2.write())
    #print "\nTACK_Sig:\n", sig2.writeText()

    # Test reading/writing TACK_Break_Sigs with 1 code
    break_sig = TACK_Break_Sig()
    break_sig.pin_label = os.urandom(8)
    break_sig.signature = os.urandom(64)
    break_sig2 = TACK_Break_Sig()
    break_sig2.parse(break_sig.write())
    assert(break_sig.write() == break_sig2.write())
        

def testKeyFile():
    f = TACK_KeyFile()
    f.generate()
    
    b = f.write("abracadabra")
    f2 = TACK_KeyFile()
    assert(f2.parse(b, "abracadabra"))
    assert(f2.__dict__ == f.__dict__)

    f2.generate(bytearray("blablabla"))    
    h = bytearray(range(100,200))
    sig = f2.sign(h)

def testCert():
    sigDays = pinDays = 550 # About 1.5 years
    currentTime = int(time.time()//60) # Get time in minutes
    sigExp = currentTime + (24*60) * sigDays    
    
    sslBytes = bytearray(range(1,200))
    kf = TACK_KeyFile()
    kf.generate()    
        
    pin = TACK_Pin()
    pin.generate(TACK_Pin_Type.v1, os.urandom(8), kf.public_key)
        
    privKey, pubKey = ec256Generate()
    sig = TACK_Sig()
    sig.generate(TACK_Sig_Type.v1_cert,
                 sigExp, sigExp+100, 
                 SHA256(sslBytes), pin,
                 lambda b :ecdsa256Sign(privKey,pubKey,b))
                     
    tc = TACK_Cert()
    tc.generate(pin, sig)

    tc2 = TACK_Cert()
    tc2.parse(tc.write())
    assert(tc.write() == tc2.write())

################ MAIN ###

import sys, getpass, getopt, glob

def printUsage(s=None):
    if s:
        print("ERROR: %s\n" % s)
    print("""Commands:
new    <cert>"
update <cert>"
break"
view   <file>"
help   <command>
""")
    sys.exit(-1)

def printError(s):
    print("ERROR: %s\n" % s)
    sys.exit(-1)

def newKeyFile(extraRandStr=""):
    if not extraRandStr:
        while len(extraRandStr)<20:
            extraRandStr = getpass.getpass (
                "Enter at least 20 random keystrokes: ")    
    kf = TACK_KeyFile()
    kf.generate(extraRandStr)
    return kf

def openKeyFile(kfBytes, password=None):
    kf = TACK_KeyFile()
    if password:
        if not kf.parse(kfBytes, password):
            printError("Bad password")
        else:
            return kf
    while 1:
        password = getpass.getpass("Enter password for key file: ")
        if kf.parse(kfBytes, password):
            break
        print("PASSWORD INCORRECT!")
    return kf

def createFileRaiseOSExIfExists(name):
    fd = os.open(name, os.O_EXCL | os.O_CREAT | os.O_WRONLY)
    f = os.fdopen(fd, "wb")
    return f    

def writeKeyFile(kf, suffix):
    passwordStr = ""
    while not passwordStr:
        password1, password2 = "a", "b"
        while password1 != password2:
            password1 = getpass.getpass("Choose password for key file: ")    
            password2 = getpass.getpass("Re-enter password for key file: ")  
            if password1 != password2:
                print("PASSWORDS DON'T MATCH!")      
            else:
                passwordStr = password1    
    b = kf.write(passwordStr)
    f = open("TACK_key_%s.dat" % suffix, "wb")
    f.write(b)
    f.close()
    return kf    

def writeTACKCert(tc, oldName, suffix, tcNameCounter, 
                    der=False, noBackup=False):    
    b = tc.write()
    if not der:
        newExt = ".pem"
        b = pemCert(b)
    else:
        newExt = ".der"       
        
    # Backup old TACK cert (if there is one)
    if oldName and not noBackup:
        oldf = open(oldName, "rb")
        oldBytes = oldf.read()
        oldf.close()
        bakName = "OLD_" + oldName
        try:
            bakf = createFileRaiseOSExIfExists(bakName)
        except OSError:
            # If the backup already exists:
            printError("Can't back up %s" % oldName) 
        bakf.write(oldBytes)
        bakf.close()
    
    # Create the new filename, giving it a name after the 
    # file it is replacing.
    newNameNoExt = "TACK_cert_%s_%s" % (suffix, getDateStr())
    newNameCounter = 0
    if oldName and oldName.startswith(newNameNoExt):
        newNameCounter = tcNameCounter + 1
    
    # Now look at the backup directory to see if there is
    # a name collison that will appear when we later try to
    # backup this file.  This could occur if the user reuses
    # a suffix that already has some backed-up files, but 
    # which does not match the current old file.
    for name in glob.glob("OLD_" + newNameNoExt + "*"):
        suffix, counter = parseTACKCertName(name, True)
        newNameCounter = max(newNameCounter, counter+1)

    # Prepare the new name, with counter and extension
    if newNameCounter > 0:    
        newNameNoExt += "_%03d" % newNameCounter    
    newName = newNameNoExt + newExt    
    
    # Write to the new file, remove the old file
    newf = open(newName, "wb")
    newf.write(b)
    newf.close()
    if oldName:
        os.remove(oldName)

def parseTACKCertName(tcName, old=False):
    if old:
        lIndex = len("OLD_TACK_cert_")
    else:
        lIndex = len("TACK_cert_")
    rIndex = tcName.find("_", lIndex)        
    tcSuffix = tcName[lIndex : rIndex]

    lIndex = rIndex+1
    rIndex = tcName.find("_", lIndex)
    if rIndex == -1:
        rIndex = tcName.find(".", lIndex)
    if rIndex == -1: # should be impossible, due to glob, but...
        printError("Malformed TACK certificate name, before date: %s" % tcName)
    dateStamp = tcName[lIndex : rIndex]
    try:
        time.strptime(dateStamp, "%Y-%m-%d")
    except ValueError:
        printError("Malformed TACK certificate name, bad date: %s" % tcName)

    if tcName[rIndex] == ".":
        tcNameCounter = 0
    else:
        if tcName[rIndex] != "_":
            printError(
                "Malformed TACK certificate name, after date: %s" % tcName)
        try:
            tcNameCounter = int(tcName[rIndex+1 : -4])
        except ValueError:
            printError("Malformed TACK certificate name, counter: %s" % tcName)
    return tcSuffix, tcNameCounter
            
def openTACKFiles(errorNoCertOrKey=False, password=None):       
    tcGlobPem = glob.glob("TACK_cert_*_*.pem")
    tcGlobDer = glob.glob("TACK_cert_*_*.der")
    tcGlob = tcGlobPem + tcGlobDer
    if len(tcGlob) == 0:
        if errorNoCertOrKey:
            printError("No TACK cert found")
        tcBytes = None
        tcName = None
        tcNameCounter = None
        tcSuffix = None
    elif len(tcGlob) > 1:
        printError("More than one TACK cert found")
    else:
        tcName = tcGlob[0]
        tcSuffix, tcNameCounter = parseTACKCertName(tcName)
        tcBytes = bytearray(open(tcName, "rb").read())

    kfGlob = glob.glob("TACK_key_*.dat")
    if len(kfGlob) == 0:
        if errorNoCertOrKey:
            printError("No TACK key found")
        kfBytes = None
    elif len(kfGlob) > 1:
        printError("More than one TACK key found")
    else:
        kfName = kfGlob[0]
        kfBytes = bytearray(open(kfName, "rb").read())        

    tc = TACK_Cert()
    if tcBytes:
        print("Updating %s..." % tcName)
        try:
            tc.parse(tcBytes)
        except SyntaxError:
            printError("TACK certificate malformed: %s" % tcName)
    else:
        tc.generate()
        print("No TACK certificate found, creating new one...")

    if kfBytes:
        print("Opening %s..." % kfName)        
        try:
            kf = openKeyFile(kfBytes, password)   
        except SyntaxError:
            printError("%s malformed" % kfName)        
    else:
        kf = None
    return (tc, kf, tcName, tcSuffix, tcNameCounter)

def confirmY(s):
    query = raw_input(s)
    if query != "y":
        printError("Cancelled")    

def parseArgsIntoDict(argv, noArgArgs, oneArgArgs):
    argsDict = {}    
    for arg in argv:
        if not arg.startswith("--"):
            printError("Malformed argument: %s" % arg)
        arg = arg[2:]
        parts = arg.split("=")
        if parts[0] in argsDict:
            printError("Duplicate argument: %s" % parts[0])
        if len(parts)==2:
            if not parts[0] in oneArgArgs:
                printError("Unknown or malformed argument: %s" % parts[0])
            argsDict[parts[0]] = parts[1]
        elif len(parts)==1:
            if not parts[0] in noArgArgs:
                printError("Unknown or malformed argument: %s" % parts[0])            
            argsDict[parts[0]] = None
        else:
            printError("Unknown or malformed argument: %s" % parts[0])
    return argsDict

def pin(argv, update=False):
    if len(argv) < 1:
        printError("Missing argument: SSL certificate file")    
    sslName = argv[0]
        
    # Collect cmdline args into a dictionary        
    noArgArgs = ["der", "no_backup"]
    oneArgArgs= ["sig_type", "sig_expiration", "sig_revocation",
                "suffix", "password"]
    if not update:
        noArgArgs += ["replace"]
    d = parseArgsIntoDict(argv[1:], noArgArgs, oneArgArgs)
    
    # Set vars from cmdline dict
    der = "der" in d
    noBackup = "no_backup" in d
    forceReplace = "replace" in d
    sig_revocation = d.get("sig_revocation")
    if sig_revocation != None: # Ie not set on cmdline, DIFFERENT FROM 0          
        sig_revocation = parseTimeArg(sig_revocation)
    defaultExp = getDefaultExpirationStr()  
    sig_expiration = parseTimeArg(d.get("sig_expiration", defaultExp))
    cmdlineSuffix = d.get("suffix")
    password = d.get("password")
    try:
        sig_type = {"v1_key" : TACK_Sig_Type.v1_key, 
                    "v1_cert" : TACK_Sig_Type.v1_cert}\
                    [d.get("sig_type", "v1_cert")]
    except KeyError:
            printError("Unrecognized sig_type")
                
    # Open the SSL cert
    try:
        sslBytes = bytearray(open(sslName, "rb").read())
    except IOError:
        printError("SSL certificate file not found: %s" % argv[0])
    sslc = SSL_Cert()
    try:
        sslc.parse(sslBytes)        
    except SyntaxError:
        prinError("SSL certificate malformed: %s" % argv[0])
    
    # Open the TACK_cert and TACK_key files, creating latter if needed
    tc, kf, tcName, parsedSuffix, tcNameCounter = \
        openTACKFiles(update, password)
    if not kf:
        print("No TACK key found, creating new one...")
        kf = newKeyFile()
        mustWriteKeyFile = True
    else:
        mustWriteKeyFile = False        

    # Check existing TACK_Pin and TACK_Sig
    if update:
        if not tc.TACK:
            printError("TACK certificate has no TACK extension")
        # Maintain old sig_revocation on updates, unless overridden on cmdline
        if sig_revocation == None: # i.e. not set on cmdline, DIFFERENT FROM 0
            sig_revocation = tc.TACK.sig.sig_revocation
        else:
            if sig_revocation < tc.TACK.sig.sig_revocation:
                confirmY(
'''WARNING: Requested sig_expiration is EARLIER than existing!
Do you know what you are doing? ("y" to continue): ''')
        tc.TACK.sig = None
    elif not update and tc.TACK:
        if not forceReplace:
            confirmY('There is an existing TACK, choose "y" to replace: ')        
        tc.TACK = None

    # Set suffix for output (new=cmdline or prompt, update=parsed)
    suffix = None
    if cmdlineSuffix:
        suffix = cmdlineSuffix
    else:
        if not update:
            if mustWriteKeyFile:
                suffix = raw_input(
"Enter a short suffix for your TACK key and cert files: ")
            else:
                suffix = raw_input(
"Enter a short suffix for your TACK cert file: ")
        else:
            suffix = parsedSuffix

    # Produce the TACK_Pin (if "new")
    if not update:
        tc.TACK = TACK()
        tc.TACK.pin = TACK_Pin()            
        label = bytearray(os.urandom(8))
        tc.TACK.pin.generate(TACK_Pin_Type.v1, label, kf.public_key)

    # Produce the TACK_Sig
    if sig_type == TACK_Sig_Type.v1_key:
        sig_target_sha256 = sslc.key_sha256
    elif sig_type == TACK_Sig_Type.v1_cert:
        sig_target_sha256 = sslc.cert_sha256
    tc.TACK.sig = TACK_Sig()
    # If not sig_expiration was set or carried-over, set to 1970
    if sig_revocation == None:
        sig_revocation = 0
    tc.TACK.sig.generate(sig_type, sig_expiration, sig_revocation, 
                    sig_target_sha256, tc.TACK.pin, kf.sign)

    # Write out files
    writeTACKCert(tc, tcName, suffix, tcNameCounter, der, noBackup)
    if mustWriteKeyFile:
        writeKeyFile(kf, suffix)

def promptForPinLabel():
    while 1:
        labelStr = raw_input("Enter pin_label to break: ").lower()
        if labelStr.startswith("0x"):
            labelStr = labelStr[2:]
        try:
            pin_label = a2b_hex(labelStr)
            if len(pin_label) != 8:
                pass            
            break
        except TypeError:
            pass
    return pin_label

def breakPin(argv):
    # Collect cmdline args into a dictionary        
    noArgArgs = ["der", "no_backup"]
    oneArgArgs= ["suffix", "password", "label"]
    d = parseArgsIntoDict(argv, noArgArgs, oneArgArgs)
    
    # Set vars from cmdline dict
    der = "der" in d
    noBackup = "no_backup" in d
    cmdlineSuffix = d.get("suffix")
    password = d.get("password")
    cmdlineLabel = d.get("label")
    if cmdlineLabel:
        cmdlineLabel = cmdlineLabel.lower()
        if cmdlineLabel.startswith("0x"):
            cmdlineLabel = cmdlineLabel[2:]
        try:
            cmdlineLabel = a2b_hex(cmdlineLabel)
            if len(cmdlineLabel) != 8:
                printError('Bad argument for "label" - must be 8 bytes')
        except TypeError:
            printError('Bad argument for "label" - must be hex string')

    try:
        sig_type = {"v1_key" : TACK_Sig_Type.v1_key, 
                    "v1_cert" : TACK_Sig_Type.v1_cert}\
                    [d.get("sig_type", "v1_cert")]
    except KeyError:
            printError("Unrecognized sig_type")
    
    tc, kf, tcName, suffix, nameCounter = openTACKFiles(True, password)
    
    if cmdlineSuffix:
        suffix = cmdlineSuffix
    if not tc.break_sigs:
        tc.break_sigs = TACK_Break_Sigs()

    if tc.break_sigs.isFull():
        printError("Maximum number of break signatures (%d) already present" %
            TACK_Break_Sigs.maxLen)
        
    break_sig = TACK_Break_Sig()   

    if cmdlineLabel:
        pin_label = cmdlineLabel
    else:
        if not tc.TACK:
            print("WARNING: There is no existing TACK...")
            pin_label = promptForPinLabel()
            print("Breaking pin_label = 0x%s" % b2a_hex(pin_label))        
        elif tc.TACK.pin.pin_key != kf.public_key:
            print("WARNING: This key DOES NOT MATCH the existing TACK...")
            pin_label = promptForPinLabel()
            print("Breaking pin_label = 0x%s" % b2a_hex(pin_label))        
        else:
            pin_label = tc.TACK.pin.pin_label
            print("Breaking existing TACK, pin_label = 0x%s" % \
                    b2a_hex(pin_label))
        confirmY('Is this correct? ("y" to continue): ')            
    
    break_sig.generate(pin_label, kf.sign(pin_label))
    tc.break_sigs.add(break_sig)
    
    # If we broke the existing TACK pin, remove it
    if tc.TACK and pin_label == tc.TACK.pin.pin_label and \
            kf.public_key == tc.TACK.pin.pin_key:
        tc.TACK = None
    
    writeTACKCert(tc, tcName, suffix, nameCounter, der, noBackup)
     
def view(argv):
    if len(argv) < 1:
        printError("Missing argument: object to view")
    if len(argv) > 1:
        printError("Can only view one object")
    try:
        b = bytearray(open(argv[0], "rb").read())
    except IOError:
        printError("File not found: %s" % argv[0])
    # If it's a key file
    if len(b) == 168 and b[:3] == TACK_KeyFile.magic:
        kfv = TACK_KeyFileViewer()
        kfv.parse(b)
        print(kfv.writeText())
    # If not it could be a certificate
    else: 
        try:
            written=0            
            tc = TACK_Cert()
            tc.parse(b)
            if tc.TACK or tc.break_sigs:
                print(tc.writeText())
                written = 1      
        except SyntaxError:
            pass
        if not written:
            try:
                sslc = SSL_Cert()
                sslc.parse(b)
                print(sslc.writeText())      
            except SyntaxError:
                printError("Unrecognized file type")

def help(argv):
    if len(argv) == 0:
        printUsage()
    cmd = argv[0]
    if cmd == "new"[:len(cmd)]:
        s = posixTimeToStr(time.time())        
        print( \
"""Creates a TACK based on a new pin for the target SSL certificate.
        
  new <cert> <args>

Optional arguments:
  --der              : write output as .der instead of .pem
  --no_backup        : don't backup the TACK certificate
  --replace          : replace an existing TACK without prompting
  --password=        : use this TACK key password
  --suffix=          : use this TACK file suffix
  --sig_type=        : target signature to "v1_key" or "v1_cert"
  --sig_expiration=  : use this UTC time for sig_expiration
  --sig_revocation=  : use this UTC time for sig_revocation
                         ("%s", "%s",
                          "%s", "%s" etc.)
""" % (s, s[:13], s[:10], s[:4]))
    elif cmd == "update"[:len(cmd)]:
        s = posixTimeToStr(time.time())                
        print( \
"""Creates a TACK based on an existing pin for the target SSL certificate.

  update <cert> <args>

Optional arguments:
  --der              : write output as .der instead of .pem
  --no_backup        : don't backup the TACK certificate
  --password=        : use this TACK key password
  --suffix=          : use this TACK file suffix
  --sig_type=        : target signature to "v1_key" or "v1_cert"
  --sig_expiration=  : use this UTC time for sig_expiration
  --sig_revocation=  : use this UTC time for sig_revocation
                         ("%s", "%s",
                          "%s", "%s" etc.)
""" % (s, s[:13], s[:10], s[:4]))
    elif cmd == "break"[:len(cmd)]:
        print( \
"""Adds a break signature to a TACK certificate, and removes any broken TACK.

  break <args>

Optional arguments:
  --label            : pin_label to break (8 bytes hexadecimal)
  --der              : write output as .der instead of .pem
  --no_backup        : don't backup the TACK certificate
  --password=        : use this TACK key password
  --suffix=          : use this TACK file suffix 
""")
    elif cmd == "view"[:len(cmd)]:
        print("""Views a TACK certificate, SSL certificate, or Key File.

  view <file>
""")        
    else:
        printError("Help requested for unknown command")
        

if __name__ == '__main__':
    if len(sys.argv) < 2:
        printUsage("Missing command")
    elif sys.argv[1] == "test":
        testCert()
        testStructures()
        testKeyFile()        
    elif sys.argv[1] == "new"[:len(sys.argv[1])]:
        pin(sys.argv[2:], False)
    elif sys.argv[1] == "update"[:len(sys.argv[1])]:
        pin(sys.argv[2:], True)
    elif sys.argv[1] == "break"[:len(sys.argv[1])]:
        breakPin(sys.argv[2:])
    elif sys.argv[1] == "view"[:len(sys.argv[1])]:
        view(sys.argv[2:])
    elif sys.argv[1] == "help"[:len(sys.argv[1])]:
        help(sys.argv[2:])
    else:
        printUsage("Unknown command: %s" % sys.argv[1])



    
