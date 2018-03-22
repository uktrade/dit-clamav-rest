require 'rest-client'

# gem 'rest-client' in Gemfile
# gem 'figaro' in Gemfile for Simple Rails app configuration
# include VirusScannerHelper in your class and define the three env variables to add virus scanning functionality
# v2 will return clean: false with reason: Heuristics.Encrypted.Zip in the case of an encrypted zip file. It can scan non-encrypted zip files.
module VirusScannerHelper
  # file_path path to file to be scanned, accepts most common URI paths
  # true if file is clean, false otherwise
  def scan_clean(file_path)
    request = RestClient::Request.new(
        method: :post,
        url: Figaro.env.CLAM_AV_HOST,
        payload: {
            multipart: true,
            file: File.new(file_path, 'rb'),
        },
        user: Figaro.env.CLAM_AV_USERNAME,
        password: Figaro.env.CLAM_AV_PASSWORD
    )

    response = request.execute
    response_json = JSON.parse(response.body)

    { clean: !response_json['malware'], reason: response_json['reason'] }
  end
end
