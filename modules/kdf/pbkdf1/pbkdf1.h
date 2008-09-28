/*************************************************
* PBKDF1 Header File                             *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#ifndef BOTAN_PBKDF1_H__
#define BOTAN_PBKDF1_H__

#include <botan/s2k.h>

namespace Botan {

/*************************************************
* PKCS #5 PBKDF1                                 *
*************************************************/
class BOTAN_DLL PKCS5_PBKDF1 : public S2K
   {
   public:
      std::string name() const;
      S2K* clone() const { return new PKCS5_PBKDF1(hash_name); }
      PKCS5_PBKDF1(const std::string&);
   private:
      OctetString derive(u32bit, const std::string&,
                          const byte[], u32bit, u32bit) const;
      const std::string hash_name;
   };

}

#endif
