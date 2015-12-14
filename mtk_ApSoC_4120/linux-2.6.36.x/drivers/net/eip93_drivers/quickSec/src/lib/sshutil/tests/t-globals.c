/*
 * t-globals.c
 *
 * Author: Kenneth Oksanen <cessu@iki.fi>
 *
 *  Copyright:
 *          Copyright (c) 2002, 2003 SFNT Finland Oy.
 *                    All rights reserved
 *
 * Test program global variable emulation in sshcore/sshglobals.[gc].
 */

/* The C-code in this file was originally generated with the following
   perl script:

     #!/usr/bin/perl -w

     $words_file="/usr/share/dict/words";

     open(INPUT, $words_file) || die("Couldn't find $words_file");
     $ctr=0;
     while (<INPUT>)
     {
         chop;
         # Must discard all reserved, prereseved or otherwise unsuitable words.
         if (/^and$/) { next; }
         if (/^catch$/) { next; }
         if (/^char$/) { next; }
         if (/^class$/) { next; }
         if (/^compress$/) { next; }
         if (/^defined$/) { next; }
         if (/^deflate$/) { next; }
         if (/^delete$/) { next; }
         if (/^explicit$/) { next; }
         if (/^false$/) { next; }
         if (/^free$/) { next; }
         if (/^friend$/) { next; }
         if (/^inflate$/) { next; }
         if (/^int$/) { next; }
         if (/^interface$/) { next; }
         if (/^main$/) { next; }
         if (/^mutable$/) { next; }
         if (/^new$/) { next; }
         if (/^operator$/) { next; }
         if (/^or$/) { next; }
         if (/^private$/) { next; }
         if (/^protected$/) { next; }
         if (/^public$/) { next; }
         if (/^return$/) { next; }
         if (/^template$/) { next; }
         if (/^this$/) { next; }
         if (/^throw$/) { next; }
         if (/^true$/) { next; }
         if (/^try$/) { next; }
         if (/^using$/) { next; }
         if (/^virtual$/) { next; }
         if (/[^_a-zA-Z0-9]/) { next; }
         $vars[$ctr++] = $_;
     }
     close(INPUT);

     printf("#include \"sshincludes.h\"\n");
     printf("#include \"sshglobals.h\"\n\n");

     foreach (@vars)
     {
         printf("SSH_GLOBAL_DECLARE(int, %s);\n", $_);
         printf("#define %s SSH_GLOBAL_USE(%s)\n", $_, $_);
         printf("SSH_GLOBAL_DEFINE(int, %s);\n", $_);
     }

     printf("\nint main(int argc, char **argv)\n");
     printf("{\n");
     printf("  int ctr = 0;\n");

     foreach (@vars)
     {
         printf("  SSH_GLOBAL_INIT(%s, ctr++);\n", $_);
     }

     printf("  printf(\"%%d\\n\", Abba);\n");
     
     foreach (@vars)
     {
         printf("  %s++;\n", $_);
     }

     printf("  printf(\"%%d\\n\", Abba);\n");
     printf("  return 0;\n");
     printf("}\n");

   Note, however, that for the this would generate hundreds of
   thousands of lines of code, so this file was cut down. */

#include "sshincludes.h"
#include "sshglobals.h"

SSH_GLOBAL_DECLARE(int, Aarhus);
#define Aarhus SSH_GLOBAL_USE(Aarhus)
SSH_GLOBAL_DEFINE(int, Aarhus);
SSH_GLOBAL_DECLARE(int, Aaron);
#define Aaron SSH_GLOBAL_USE(Aaron)
SSH_GLOBAL_DEFINE(int, Aaron);
SSH_GLOBAL_DECLARE(int, Ababa);
#define Ababa SSH_GLOBAL_USE(Ababa)
SSH_GLOBAL_DEFINE(int, Ababa);
SSH_GLOBAL_DECLARE(int, aback);
#define aback SSH_GLOBAL_USE(aback)
SSH_GLOBAL_DEFINE(int, aback);
SSH_GLOBAL_DECLARE(int, abaft);
#define abaft SSH_GLOBAL_USE(abaft)
SSH_GLOBAL_DEFINE(int, abaft);
SSH_GLOBAL_DECLARE(int, abandon);
#define abandon SSH_GLOBAL_USE(abandon)
SSH_GLOBAL_DEFINE(int, abandon);
SSH_GLOBAL_DECLARE(int, abandoned);
#define abandoned SSH_GLOBAL_USE(abandoned)
SSH_GLOBAL_DEFINE(int, abandoned);
SSH_GLOBAL_DECLARE(int, abandoning);
#define abandoning SSH_GLOBAL_USE(abandoning)
SSH_GLOBAL_DEFINE(int, abandoning);
SSH_GLOBAL_DECLARE(int, abandonment);
#define abandonment SSH_GLOBAL_USE(abandonment)
SSH_GLOBAL_DEFINE(int, abandonment);
SSH_GLOBAL_DECLARE(int, abandons);
#define abandons SSH_GLOBAL_USE(abandons)
SSH_GLOBAL_DEFINE(int, abandons);
SSH_GLOBAL_DECLARE(int, abase);
#define abase SSH_GLOBAL_USE(abase)
SSH_GLOBAL_DEFINE(int, abase);
SSH_GLOBAL_DECLARE(int, abased);
#define abased SSH_GLOBAL_USE(abased)
SSH_GLOBAL_DEFINE(int, abased);
SSH_GLOBAL_DECLARE(int, abasement);
#define abasement SSH_GLOBAL_USE(abasement)
SSH_GLOBAL_DEFINE(int, abasement);
SSH_GLOBAL_DECLARE(int, abasements);
#define abasements SSH_GLOBAL_USE(abasements)
SSH_GLOBAL_DEFINE(int, abasements);
SSH_GLOBAL_DECLARE(int, abases);
#define abases SSH_GLOBAL_USE(abases)
SSH_GLOBAL_DEFINE(int, abases);
SSH_GLOBAL_DECLARE(int, abash);
#define abash SSH_GLOBAL_USE(abash)
SSH_GLOBAL_DEFINE(int, abash);
SSH_GLOBAL_DECLARE(int, abashed);
#define abashed SSH_GLOBAL_USE(abashed)
SSH_GLOBAL_DEFINE(int, abashed);
SSH_GLOBAL_DECLARE(int, abashes);
#define abashes SSH_GLOBAL_USE(abashes)
SSH_GLOBAL_DEFINE(int, abashes);
SSH_GLOBAL_DECLARE(int, abashing);
#define abashing SSH_GLOBAL_USE(abashing)
SSH_GLOBAL_DEFINE(int, abashing);
SSH_GLOBAL_DECLARE(int, abasing);
#define abasing SSH_GLOBAL_USE(abasing)
SSH_GLOBAL_DEFINE(int, abasing);
SSH_GLOBAL_DECLARE(int, abate);
#define abate SSH_GLOBAL_USE(abate)
SSH_GLOBAL_DEFINE(int, abate);
SSH_GLOBAL_DECLARE(int, abated);
#define abated SSH_GLOBAL_USE(abated)
SSH_GLOBAL_DEFINE(int, abated);
SSH_GLOBAL_DECLARE(int, abatement);
#define abatement SSH_GLOBAL_USE(abatement)
SSH_GLOBAL_DEFINE(int, abatement);
SSH_GLOBAL_DECLARE(int, abatements);
#define abatements SSH_GLOBAL_USE(abatements)
SSH_GLOBAL_DEFINE(int, abatements);
SSH_GLOBAL_DECLARE(int, abater);
#define abater SSH_GLOBAL_USE(abater)
SSH_GLOBAL_DEFINE(int, abater);
SSH_GLOBAL_DECLARE(int, abates);
#define abates SSH_GLOBAL_USE(abates)
SSH_GLOBAL_DEFINE(int, abates);
SSH_GLOBAL_DECLARE(int, abating);
#define abating SSH_GLOBAL_USE(abating)
SSH_GLOBAL_DEFINE(int, abating);
SSH_GLOBAL_DECLARE(int, Abba);
#define Abba SSH_GLOBAL_USE(Abba)
SSH_GLOBAL_DEFINE(int, Abba);
SSH_GLOBAL_DECLARE(int, abbe);
#define abbe SSH_GLOBAL_USE(abbe)
SSH_GLOBAL_DEFINE(int, abbe);
SSH_GLOBAL_DECLARE(int, abbey);
#define abbey SSH_GLOBAL_USE(abbey)
SSH_GLOBAL_DEFINE(int, abbey);
SSH_GLOBAL_DECLARE(int, abbeys);
#define abbeys SSH_GLOBAL_USE(abbeys)
SSH_GLOBAL_DEFINE(int, abbeys);
SSH_GLOBAL_DECLARE(int, abbot);
#define abbot SSH_GLOBAL_USE(abbot)
SSH_GLOBAL_DEFINE(int, abbot);
SSH_GLOBAL_DECLARE(int, abbots);
#define abbots SSH_GLOBAL_USE(abbots)
SSH_GLOBAL_DEFINE(int, abbots);
SSH_GLOBAL_DECLARE(int, Abbott);
#define Abbott SSH_GLOBAL_USE(Abbott)
SSH_GLOBAL_DEFINE(int, Abbott);
SSH_GLOBAL_DECLARE(int, abbreviate);
#define abbreviate SSH_GLOBAL_USE(abbreviate)
SSH_GLOBAL_DEFINE(int, abbreviate);
SSH_GLOBAL_DECLARE(int, abbreviated);
#define abbreviated SSH_GLOBAL_USE(abbreviated)
SSH_GLOBAL_DEFINE(int, abbreviated);
SSH_GLOBAL_DECLARE(int, abbreviates);
#define abbreviates SSH_GLOBAL_USE(abbreviates)
SSH_GLOBAL_DEFINE(int, abbreviates);
SSH_GLOBAL_DECLARE(int, abbreviating);
#define abbreviating SSH_GLOBAL_USE(abbreviating)
SSH_GLOBAL_DEFINE(int, abbreviating);
SSH_GLOBAL_DECLARE(int, abbreviation);
#define abbreviation SSH_GLOBAL_USE(abbreviation)
SSH_GLOBAL_DEFINE(int, abbreviation);
SSH_GLOBAL_DECLARE(int, abbreviations);
#define abbreviations SSH_GLOBAL_USE(abbreviations)
SSH_GLOBAL_DEFINE(int, abbreviations);
SSH_GLOBAL_DECLARE(int, Abby);
#define Abby SSH_GLOBAL_USE(Abby)
SSH_GLOBAL_DEFINE(int, Abby);
SSH_GLOBAL_DECLARE(int, abdomen);
#define abdomen SSH_GLOBAL_USE(abdomen)
SSH_GLOBAL_DEFINE(int, abdomen);
SSH_GLOBAL_DECLARE(int, abdomens);
#define abdomens SSH_GLOBAL_USE(abdomens)
SSH_GLOBAL_DEFINE(int, abdomens);
SSH_GLOBAL_DECLARE(int, abdominal);
#define abdominal SSH_GLOBAL_USE(abdominal)
SSH_GLOBAL_DEFINE(int, abdominal);
SSH_GLOBAL_DECLARE(int, abduct);
#define abduct SSH_GLOBAL_USE(abduct)
SSH_GLOBAL_DEFINE(int, abduct);
SSH_GLOBAL_DECLARE(int, abducted);
#define abducted SSH_GLOBAL_USE(abducted)
SSH_GLOBAL_DEFINE(int, abducted);
SSH_GLOBAL_DECLARE(int, abduction);
#define abduction SSH_GLOBAL_USE(abduction)
SSH_GLOBAL_DEFINE(int, abduction);
SSH_GLOBAL_DECLARE(int, abductions);
#define abductions SSH_GLOBAL_USE(abductions)
SSH_GLOBAL_DEFINE(int, abductions);
SSH_GLOBAL_DECLARE(int, abductor);
#define abductor SSH_GLOBAL_USE(abductor)
SSH_GLOBAL_DEFINE(int, abductor);
SSH_GLOBAL_DECLARE(int, abductors);
#define abductors SSH_GLOBAL_USE(abductors)
SSH_GLOBAL_DEFINE(int, abductors);
SSH_GLOBAL_DECLARE(int, abducts);
#define abducts SSH_GLOBAL_USE(abducts)
SSH_GLOBAL_DEFINE(int, abducts);
SSH_GLOBAL_DECLARE(int, Abe);
#define Abe SSH_GLOBAL_USE(Abe)
SSH_GLOBAL_DEFINE(int, Abe);

int main(int argc, char **argv)
{
  int ctr = 0;
  SSH_GLOBAL_INIT(Aarhus, ctr++);
  SSH_GLOBAL_INIT(Aaron, ctr++);
  SSH_GLOBAL_INIT(Ababa, ctr++);
  SSH_GLOBAL_INIT(aback, ctr++);
  SSH_GLOBAL_INIT(abaft, ctr++);
  SSH_GLOBAL_INIT(abandon, ctr++);
  SSH_GLOBAL_INIT(abandoned, ctr++);
  SSH_GLOBAL_INIT(abandoning, ctr++);
  SSH_GLOBAL_INIT(abandonment, ctr++);
  SSH_GLOBAL_INIT(abandons, ctr++);
  SSH_GLOBAL_INIT(abase, ctr++);
  SSH_GLOBAL_INIT(abased, ctr++);
  SSH_GLOBAL_INIT(abasement, ctr++);
  SSH_GLOBAL_INIT(abasements, ctr++);
  SSH_GLOBAL_INIT(abases, ctr++);
  SSH_GLOBAL_INIT(abash, ctr++);
  SSH_GLOBAL_INIT(abashed, ctr++);
  SSH_GLOBAL_INIT(abashes, ctr++);
  SSH_GLOBAL_INIT(abashing, ctr++);
  SSH_GLOBAL_INIT(abasing, ctr++);
  SSH_GLOBAL_INIT(abate, ctr++);
  SSH_GLOBAL_INIT(abated, ctr++);
  SSH_GLOBAL_INIT(abatement, ctr++);
  SSH_GLOBAL_INIT(abatements, ctr++);
  SSH_GLOBAL_INIT(abater, ctr++);
  SSH_GLOBAL_INIT(abates, ctr++);
  SSH_GLOBAL_INIT(abating, ctr++);
  SSH_GLOBAL_INIT(Abba, ctr++);
  SSH_GLOBAL_INIT(abbe, ctr++);
  SSH_GLOBAL_INIT(abbey, ctr++);
  SSH_GLOBAL_INIT(abbeys, ctr++);
  SSH_GLOBAL_INIT(abbot, ctr++);
  SSH_GLOBAL_INIT(abbots, ctr++);
  SSH_GLOBAL_INIT(Abbott, ctr++);
  SSH_GLOBAL_INIT(abbreviate, ctr++);
  SSH_GLOBAL_INIT(abbreviated, ctr++);
  SSH_GLOBAL_INIT(abbreviates, ctr++);
  SSH_GLOBAL_INIT(abbreviating, ctr++);
  SSH_GLOBAL_INIT(abbreviation, ctr++);
  SSH_GLOBAL_INIT(abbreviations, ctr++);
  SSH_GLOBAL_INIT(Abby, ctr++);
  SSH_GLOBAL_INIT(abdomen, ctr++);
  SSH_GLOBAL_INIT(abdomens, ctr++);
  SSH_GLOBAL_INIT(abdominal, ctr++);
  SSH_GLOBAL_INIT(abduct, ctr++);
  SSH_GLOBAL_INIT(abducted, ctr++);
  SSH_GLOBAL_INIT(abduction, ctr++);
  SSH_GLOBAL_INIT(abductions, ctr++);
  SSH_GLOBAL_INIT(abductor, ctr++);
  SSH_GLOBAL_INIT(abductors, ctr++);
  SSH_GLOBAL_INIT(abducts, ctr++);
  SSH_GLOBAL_INIT(Abe, ctr++);

  printf("%d\n", Abba);

  Aarhus++;
  Aaron++;
  Ababa++;
  aback++;
  abaft++;
  abandon++;
  abandoned++;
  abandoning++;
  abandonment++;
  abandons++;
  abase++;
  abased++;
  abasement++;
  abasements++;
  abases++;
  abash++;
  abashed++;
  abashes++;
  abashing++;
  abasing++;
  abate++;
  abated++;
  abatement++;
  abatements++;
  abater++;
  abates++;
  abating++;
  Abba++;
  abbe++;
  abbey++;
  abbeys++;
  abbot++;
  abbots++;
  Abbott++;
  abbreviate++;
  abbreviated++;
  abbreviates++;
  abbreviating++;
  abbreviation++;
  abbreviations++;
  Abby++;
  abdomen++;
  abdomens++;
  abdominal++;
  abduct++;
  abducted++;
  abduction++;
  abductions++;
  abductor++;
  abductors++;
  abducts++;
  Abe++;

  printf("%d\n", Abba);
  return 0;
}
