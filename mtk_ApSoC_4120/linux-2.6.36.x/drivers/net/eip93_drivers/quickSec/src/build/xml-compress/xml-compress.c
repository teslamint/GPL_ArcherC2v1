/*
 *
 * xml-compress.c
 *
 * Author: Markku Rossi <mtr@ssh.fi>
 *
*  Copyright:
*          Copyright (c) 2002, 2003 SFNT Finland Oy.
*  Copyright:
*          Copyright (c) 2002, 2003 SFNT Finland Oy.
 *               All rights reserved.
 *
 * A simple compress / bytefy utility for XML.
 *
 */

#include "sshincludes.h"
#include "sshgetopt.h"
#include "sshbuffer.h"

#define SSH_DEBUG_MODULE "SshXmlCompress"

/************************** Types and definitions ***************************/

#define IS_SPACE(ch) \
((ch) == 0x20 || (ch) == 0x9 || (ch) == 0xd || (ch) == 0xa)

struct SshXmlCompressOutputRec
{
  void *(*start)(FILE *fp);
  void (*output)(char *name, FILE *fp, int ch, void *ctx);
  void (*end)(FILE *fp, void *ctx);
};

typedef struct SshXmlCompressOutputRec SshXmlCompressOutputStruct;
typedef struct SshXmlCompressOutputRec *SshXmlCompressOutput;


/***************************** Static variables *****************************/

char *program;

char *output_file = NULL;

char *array_name;

/* Output method. */
SshXmlCompressOutput output;


/******************************* Print output *******************************/

static void *
output_print_start(FILE *fp)
{
  return NULL;
}

static void
output_print_output(char *name, FILE *fp, int ch, void *ctx)
{
  fputc(ch, fp);
}

static void
output_print_end(FILE *fp, void *ctx)
{
}

static SshXmlCompressOutputStruct output_print =
{
  output_print_start,
  output_print_output,
  output_print_end,
};


/****************************** Bytefy output *******************************/

static int bytes = 0;

static void *
output_bytefy_start(FILE *fp)
{
  fprintf(fp, "#include <sshincludes.h>\n\n");
  fprintf(fp, "const unsigned char %s[] =\n{", array_name);
  return NULL;
}

static void
output_bytefy_output(char *name, FILE *fp, int ch, void *ctx)
{
  if ((bytes % 10) == 0)
    fprintf(fp, "\n ");

  fprintf(fp, " 0x%02x,", ch);

  bytes++;
}

static void
output_bytefy_end(FILE *fp, void *ctx)
{
  fprintf(fp, "\n};\n\n");
  fprintf(fp, "const size_t %s_len = %u;\n", array_name, bytes);
}

static SshXmlCompressOutputStruct output_bytefy =
{
  output_bytefy_start,
  output_bytefy_output,
  output_bytefy_end,
};

/****************************** Arrayfy output *******************************/

typedef struct SshXmlArrayfyArrayRec
{
  char *name;
  struct SshXmlArrayfyArrayRec *next;

  SshBuffer buf;
} *SshXmlArrayfyArray;

typedef struct SshXmlArrayfyRec
{
  SshXmlArrayfyArray xml_head;
  SshXmlArrayfyArray xml_tail;
} *SshXmlArrayfy;

static void *
output_arrayfy_start(FILE *fp)
{
  SshXmlArrayfy ctx;

  ctx = ssh_xmalloc(sizeof(*ctx));
  ctx->xml_head = NULL;
  ctx->xml_tail = NULL;

  return ctx;
}

char *
output_beautify_name(const char *orig)
{
  int i, j;
  char *buf;

  buf = ssh_xmalloc(strlen(orig) + 1);

  for (i = 0, j = 0; orig[i] != '\0'; i++)
    {
      if (orig[i] == '.' || orig[i] == '/' || orig[i] == '-')
        buf[j++] = '_';
      else
        buf[j++] = orig[i];
    }
  buf[j] = '\0';
  return buf;
}

static void
output_arrayfy_output(char *name, FILE *fp, int ch, void *context)
{
  SshXmlArrayfy ctx = (SshXmlArrayfy)context;
  SshXmlArrayfyArray instance;
  SshUInt8 b;
  char *tmp;

  tmp = output_beautify_name(name);

  for (instance = ctx->xml_head; instance != NULL; instance = instance->next)
    {
      SSH_ASSERT(instance->name != NULL);
      if (strcmp(instance->name, tmp) == 0)
        {
          ssh_xfree(tmp);
          tmp = NULL;
          break;
        }
    }

  if (instance == NULL)
    {
      instance = ssh_xmalloc(sizeof(*instance));
      instance->buf = ssh_xbuffer_allocate();
      instance->name = tmp;
      instance->next = NULL;

      tmp = NULL;

      if (ctx->xml_tail == NULL)
        ctx->xml_head = instance;
      else
        ctx->xml_tail->next = instance;
      ctx->xml_tail = instance;
    }

  b = (SshUInt8)ch;
  ssh_xbuffer_append(instance->buf, &b, 1);
}

static void
output_arrayfy_end(FILE *fp, void *context)
{
  SshXmlArrayfy ctx = (SshXmlArrayfy)context;
  SshXmlArrayfyArray instance;
  int bytes, num_instances;

  fprintf(fp, "#include <sshincludes.h>\n\n");

  /* Create the actual content arrays */

  num_instances = 0;
  for (instance = ctx->xml_head; instance != NULL; instance = instance->next)
    {
      fprintf(fp, "const unsigned char ssh_xmlc_%s[] = \n{",
              instance->name);

      for (bytes = 0; bytes < ssh_buffer_len(instance->buf); bytes++)
        {
          if ((bytes % 10) == 0)
            fprintf(fp, "\n ");
          fprintf(fp, " 0x%02x, ", ssh_buffer_ptr(instance->buf)[bytes]);
        }

      fprintf(fp, "\n};\n\n");
      fprintf(fp, "const size_t ssh_xmlc_%s_len = %u;\n",
              instance->name, bytes);
      num_instances++;
    }

  /* Create array of names. */
  fprintf(fp, "\nconst char *ssh_xmlc_filenames[] = \n{\n");

  for (instance = ctx->xml_head; instance != NULL; instance = instance->next)
    fprintf(fp, " \"%s\", \n", instance->name);

  fprintf(fp, "\n};\n\n");

  /* Create array of pointers.. */

  fprintf(fp, "const unsigned char *ssh_xmlc_arrays[] = \n{\n");

  for (instance = ctx->xml_head; instance != NULL; instance = instance->next)
    fprintf(fp, " ssh_xmlc_%s, \n", instance->name);

  fprintf(fp, "\n};\n\n");

  /* Create array of lengths */

  fprintf(fp, "const size_t ssh_xmlc_lengths[] = \n{\n");

  for (instance = ctx->xml_head; instance != NULL; instance = instance->next)
    fprintf(fp,
            " %"
#ifdef __alpha__
            "l"
#endif /* __alpha__ */
            "u, \n",
            (unsigned)ssh_buffer_len(instance->buf));

  fprintf(fp, "\n};\n\n");

  /* Number of instances */
  fprintf(fp, "const size_t ssh_xmlc_num_files = %u;\n",
          num_instances);

}

static SshXmlCompressOutputStruct output_arrayfy =
{
  output_arrayfy_start,
  output_arrayfy_output,
  output_arrayfy_end,
};


/************************** Static help functions ***************************/

static void
usage(void)
{
  fprintf(stdout, "\
Usage: %s [OPTION]... [XML-file]\n\
  -b ARRAY      bytefy input into a C array ARRAY\n\
  -h            print this help and exit\n\
  -o FILE       save output to file FILE\n",
          program);
}

static void output_ch(char *name, FILE *ofp, int ch, void *ctx)
{
  static int last_ch = '\n';

  if (last_ch == '\n' && ch == '\n')
    return;

  last_ch = ch;
  (*output->output)(name, ofp, ch, ctx);
}


static void
process_input(char *name, FILE *ifp, FILE *ofp, void *ctx)
{
  int ch;

  while ((ch = getc(ifp)) != EOF)
    {
      if (IS_SPACE(ch))
        {
          int newline = 0;

          do
            {
              if (ch == '\n')
                newline = 1;
            }
          while ((ch = getc(ifp)) != EOF && IS_SPACE(ch));

          if (ch != EOF)
            ungetc(ch, ifp);

          if (newline)
            ch = '\n';
          else
            ch = ' ';
        }
      else if (ch == '<')
        {
          ch = getc(ifp);
          if (ch == '!')
            {
              ch = getc(ifp);
              if (ch == '-')
                {
                  ch = getc(ifp);
                  if (ch == '-')
                    {
                      /* This is a comment. */
                      while ((ch = getc(ifp)) != EOF)
                        {
                          if (ch == '-')
                            {
                            hyphen_seen:
                              ch = getc(ifp);
                              if (ch == '-')
                                {
                                  ch = getc(ifp);
                                  if (ch == '>')
                                    /* End of comment found. */
                                    goto next_at_main_loop;
                                  else
                                    goto hyphen_seen;
                                }
                            }
                        }
                    }
                  else
                    {
                      output_ch(name, ofp, '<', ctx);
                      output_ch(name, ofp, '!', ctx);
                      output_ch(name, ofp, '-', ctx);
                    }
                }
              else
                {
                      output_ch(name, ofp, '<', ctx);
                      output_ch(name, ofp, '!', ctx);
                }
            }
          else
            {
              output_ch(name, ofp, '<', ctx);
            }
        }

      output_ch(name, ofp, ch, ctx);

    next_at_main_loop:
      ;
    }
}


/********************************* The main *********************************/

int
main(int argc, char *argv[])
{
  int opt;
  void *ctx;
  FILE *ifp;
  FILE *ofp;
  Boolean array_mode;

  program = strrchr(argv[0], '/');
  if (program)
    program++;
  else
    program = argv[0];

  output = &output_print;
  array_mode = FALSE;

  /* Parse options. */
  while ((opt = ssh_getopt(argc, argv, "ab:ho:", NULL)) != EOF)
    {
      switch (opt)
        {
        case 'a':
          array_mode = TRUE;
          output = &output_arrayfy;
          array_name = "dummy";
          break;

        case 'b':
          output = &output_bytefy;
          array_name = ssh_optarg;
          break;

        case 'h':
          usage();
          exit(0);
          break;

        case 'o':
          output_file = ssh_optarg;
          break;

        case '?':
          fprintf(stderr, "Try `%s -h' for more information.\n", program);
          exit (1);
          break;
        }
    }

  if (output_file)
    {
      ofp = fopen(output_file, "wb");
      if (ofp == NULL)
        {
          fprintf(stderr, "%s: Could not create output file `%s': %s\n",
                  program, output_file, strerror(errno));
          exit(1);
        }
    }
  else
    ofp = stdout;

  /* Process all input files. */
  ctx = (*output->start)(ofp);

  if (ssh_optind >= argc)
    {
      process_input("stdin", stdin, ofp, ctx);
    }
  else
    {
      for (; ssh_optind < argc; ssh_optind++)
        {
          ifp = fopen(argv[ssh_optind], "rb");
          if (ifp == NULL)
            {
              fprintf(stderr, "%s: Could not open input file `%s': %s\n",
                      program, argv[ssh_optind], strerror(errno));
              continue;
            }

          if (array_mode == FALSE)
            process_input(array_name, ifp, ofp, ctx);
          else
            process_input(argv[ssh_optind], ifp, ofp, ctx);

          fclose(ifp);
        }
    }

  (*output->end)(ofp, ctx);

  if (output_file)
    fclose(ofp);

  return 0;
}
