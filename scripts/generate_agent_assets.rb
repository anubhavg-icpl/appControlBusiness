#!/usr/bin/env ruby

require 'cgi'
require 'fileutils'
require 'json'
require 'psych'
require 'time'

ROOT = File.expand_path('..', __dir__)
AI_DIR = File.join(ROOT, 'ai')
DOCS_GLOB = File.join(ROOT, 'docs', '**', '*.md')
BASE_URL = 'https://anubhavg-icpl.github.io/appControlBusiness/'
FEED_URL = BASE_URL + 'ai/updates.json'
ATOM_URL = BASE_URL + 'ai/atom.xml'

def extract_frontmatter(text)
  return [{}, text] unless text.start_with?("---\n")

  parts = text.split(/^---\s*$\n?/, 3)
  return [{}, text] if parts.length < 3

  raw_frontmatter = parts[1]
  body = parts[2]
  data = Psych.safe_load(raw_frontmatter, permitted_classes: [Time], aliases: true) || {}
  [data, body]
end

def normalize_markdown(markdown)
  text = markdown.dup
  text.gsub!(/```.*?```/m, ' ')
  text.gsub!(/`([^`]+)`/, '\1')
  text.gsub!(/!\[[^\]]*\]\(([^)]+)\)/, ' ')
  text.gsub!(/\[([^\]]+)\]\(([^)]+)\)/, '\1')
  text.gsub!(/^>\s+/, '')
  text.gsub!(/^#+\s+/, '')
  text.gsub!(/\|/, ' ')
  text.gsub!(/[*_~]/, '')
  text.gsub!(/\r/, '')
  text.gsub!(/\n{2,}/, "\n")
  text.gsub!(/[ \t]+/, ' ')
  text.strip
end

def heading_entries(markdown)
  markdown.scan(/^(#{'#'}{1,6})\s+(.+)$/).map do |hashes, title|
    {
      level: hashes.length,
      title: title.strip
    }
  end
end

def first_heading(markdown)
  match = markdown.match(/^#\s+(.+)$/)
  match && match[1].strip
end

def infer_kind(path)
  return 'rule-option' if path.include?('/rule-options/')
  return 'file-rule-level' if path.include?('/file-rule-levels/')
  return 'note' if path.include?('/notes/')
  return 'reference' if path.include?('/references/')
  return 'index' if File.basename(path) == 'index.md'
  return 'log' if File.basename(path) == 'log.md'

  'guide'
end

def iso8601(value)
  return nil if value.nil?
  return value.iso8601 if value.respond_to?(:iso8601)

  Time.parse(value.to_s).iso8601
rescue ArgumentError
  nil
end

def relative_path(path)
  path.sub(ROOT + '/', '')
end

def public_url(path)
  BASE_URL + relative_path(path).split('/').map { |part| CGI.escape(part).gsub('+', '%20') }.join('/')
end

def write_json(path, object)
  FileUtils.mkdir_p(File.dirname(path))
  File.write(path, JSON.pretty_generate(object) + "\n")
end

def trim_text(text, limit)
  return text if text.length <= limit

  text[0, limit].rstrip + '...'
end

def parse_log_entries(log_markdown)
  entries = []
  current_date = nil
  current_lines = []

  log_markdown.each_line do |line|
    if line.start_with?('## ')
      unless current_date.nil?
        entries << { date: current_date, lines: current_lines.dup }
      end
      current_date = line.sub('## ', '').strip
      current_lines = []
    elsif line.start_with?('* ')
      current_lines << line.sub('* ', '').strip
    end
  end

  unless current_date.nil?
    entries << { date: current_date, lines: current_lines.dup }
  end

  entries
end

docs = Dir.glob(DOCS_GLOB).sort
documents = []
frontmatter_index = []

docs.each do |path|
  raw = File.read(path)
  frontmatter, body = extract_frontmatter(raw)
  normalized = normalize_markdown(body)
  headings = heading_entries(body)
  title = frontmatter['title'] || first_heading(body) || File.basename(path, '.md')
  description = frontmatter['description'] || ''
  url = public_url(path)
  rel = relative_path(path)
  body_lines = body.lines.size
  word_count = normalized.split(/\s+/).reject(&:empty?).length

  doc = {
    id: rel.sub(/\.md$/, ''),
    path: rel,
    url: url,
    title: title,
    description: description,
    tags: frontmatter['tags'] || [],
    status: frontmatter['status'],
    type: frontmatter['type'],
    kind: infer_kind(path),
    headings: headings,
    excerpt: trim_text(normalized, 320),
    text: normalized,
    wordCount: word_count,
    lineCount: body_lines,
    generatedAt: iso8601(frontmatter.dig('generated', 'at')),
    verifiedAt: iso8601(frontmatter.dig('verified', 'at'))
  }

  documents << doc

  export = {
    id: doc[:id],
    path: rel,
    url: url,
    title: title,
    frontmatter: frontmatter,
    headings: headings,
    kind: doc[:kind]
  }

  export_path = File.join(AI_DIR, 'frontmatter', rel.sub(/\.md$/, '.json'))
  write_json(export_path, export)

  frontmatter_index << {
    id: export[:id],
    path: rel,
    url: url,
    title: title,
    kind: doc[:kind],
    export: relative_path(export_path)
  }
end

search_index = {
  generatedAt: Time.now.utc.iso8601,
  baseUrl: BASE_URL,
  totalDocuments: documents.length,
  documents: documents
}
write_json(File.join(AI_DIR, 'search-index.json'), search_index)

frontmatter_payload = {
  generatedAt: Time.now.utc.iso8601,
  totalDocuments: frontmatter_index.length,
  documents: frontmatter_index
}
write_json(File.join(AI_DIR, 'frontmatter', 'index.json'), frontmatter_payload)

llms_full_lines = []
llms_full_lines << '# Mastering App Control for Business — Full Offline Bundle'
llms_full_lines << ''
llms_full_lines << "Source site: #{BASE_URL}"
llms_full_lines << "Generated at: #{Time.now.utc.iso8601}"
llms_full_lines << ''
llms_full_lines << 'This bundle concatenates the root llms.txt guide with the full Markdown corpus so offline agents can reason over one fetchable text file.'
llms_full_lines << ''
llms_full_lines << '## Root llms.txt'
llms_full_lines << ''
llms_full_lines << File.read(File.join(ROOT, 'llms.txt')).strip
llms_full_lines << ''

documents.each do |doc|
  source_path = File.join(ROOT, doc[:path])
  raw = File.read(source_path)
  frontmatter, body = extract_frontmatter(raw)
  llms_full_lines << '---'
  llms_full_lines << "## #{doc[:title]}"
  llms_full_lines << "Path: #{doc[:path]}"
  llms_full_lines << "URL: #{doc[:url]}"
  llms_full_lines << "Type: #{frontmatter['type']}"
  llms_full_lines << "Tags: #{Array(frontmatter['tags']).join(', ')}"
  llms_full_lines << ''
  llms_full_lines << body.strip
  llms_full_lines << ''
end

File.write(File.join(AI_DIR, 'llms-full.txt'), llms_full_lines.join("\n"))

log_path = File.join(ROOT, 'docs', 'log.md')
log_entries = parse_log_entries(File.read(log_path)).map do |entry|
  time = Time.parse(entry[:date] + 'T00:00:00Z') rescue Time.now.utc
  {
    id: "#{BASE_URL}docs/log.md##{entry[:date]}",
    url: BASE_URL + 'docs/log.md',
    title: "Directory Update Log — #{entry[:date]}",
    date_published: time.utc.iso8601,
    content_text: entry[:lines].join("\n"),
    tags: ['updates', 'changelog']
  }
end

updates_json = {
  version: 'https://jsonfeed.org/version/1.1',
  title: 'App Control for Business Updates',
  home_page_url: BASE_URL,
  feed_url: FEED_URL,
  description: 'Machine-readable change feed for the App Control for Business documentation bundle.',
  items: log_entries
}
write_json(File.join(AI_DIR, 'updates.json'), updates_json)

atom_entries = log_entries.map do |entry|
  <<~XML
    <entry>
      <title>#{CGI.escapeHTML(entry[:title])}</title>
      <id>#{CGI.escapeHTML(entry[:id])}</id>
      <updated>#{entry[:date_published]}</updated>
      <link href="#{CGI.escapeHTML(entry[:url])}" />
      <summary>#{CGI.escapeHTML(entry[:content_text])}</summary>
    </entry>
  XML
end.join

atom_feed = <<~XML
  <?xml version="1.0" encoding="utf-8"?>
  <feed xmlns="http://www.w3.org/2005/Atom">
    <title>App Control for Business Updates</title>
    <id>#{ATOM_URL}</id>
    <updated>#{Time.now.utc.iso8601}</updated>
    <link href="#{BASE_URL}" rel="alternate" />
    <link href="#{ATOM_URL}" rel="self" />
    <subtitle>Machine-readable change feed for the App Control for Business documentation bundle.</subtitle>
  #{atom_entries.chomp}
  </feed>
XML
File.write(File.join(AI_DIR, 'atom.xml'), atom_feed)

puts "Generated #{documents.length} document records"